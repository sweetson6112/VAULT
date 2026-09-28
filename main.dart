import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart';
import 'package:cryptography_flutter/cryptography_flutter.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  FlutterCryptography.enable(); // native-accelerated PBKDF2 / AES-GCM
  runApp(const StrongroomApp());
}

// ---------------------------------------------------------------- vault core
const kTypes = <String, List<List<Object>>>{
  'Password': [['Website / service', false], ['Username', false], ['Password', true], ['Email', false], ['URL', false], ['Notes', false]],
  'Server': [['Server address', false], ['IP address', false], ['Port', false], ['Username', true], ['Password', true], ['SSH key / info', true], ['Notes', false]],
  'Bank': [['Bank name', false], ['Account holder', false], ['Account number', true], ['IFSC / routing', true], ['Branch', false], ['Notes', false]],
  'Secure note': [['Content', true]],
  'Identity': [['Document type', false], ['Number', true], ['Notes', false]],
  'Recovery': [['Service', false], ['Recovery codes', true], ['Notes', false]],
  'Authentication': [['Service', false], ['TOTP secret', true], ['Notes', false]],
  'Custom': [],
};

class Vault {
  static const _st = FlutterSecureStorage();
  static const _iters = 600000;
  static final _aes = AesGcm.with256bits();
  Map<String, dynamic>? db;
  SecretKey? _vk;
  List<Map<String, dynamic>> recs = [];
  List<Map<String, dynamic>> log = [];
  Map<String, dynamic> cfg = {'lock': 5, 'clip': 30};
  bool get unlocked => _vk != null;

  Future<void> load() async {
    final d = await _st.read(key: 'db');
    db = d == null ? null : jsonDecode(d);
    final l = await _st.read(key: 'log');
    log = l == null ? [] : List<Map<String, dynamic>>.from(jsonDecode(l));
    final c = await _st.read(key: 'cfg');
    if (c != null) cfg = jsonDecode(c);
  }

  Future<void> saveCfg() => _st.write(key: 'cfg', value: jsonEncode(cfg));
  Future<void> _persist() => _st.write(key: 'db', value: jsonEncode(db));

  Future<void> audit(String e, {bool ok = true}) async {
    log.insert(0, {'t': DateTime.now().toString().substring(0, 19), 'e': e, 'ok': ok});
    if (log.length > 200) log = log.sublist(0, 200);
    await _st.write(key: 'log', value: jsonEncode(log)); // events only, never secrets
  }

  Future<SecretKey> _kek(String pw, List<int> salt, int it) =>
      Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: it, bits: 256)
          .deriveKeyFromPassword(password: pw, nonce: salt);

  Future<String> _seal(SecretKey k, List<int> data, String aad) async =>
      base64.encode(await (await _aes.encrypt(data, secretKey: k, aad: utf8.encode(aad))).concatenation());

  Future<List<int>> _open(SecretKey k, String b, String aad) =>
      _aes.decrypt(SecretBox.fromConcatenation(base64.decode(b), nonceLength: 12, macLength: 16),
          secretKey: k, aad: utf8.encode(aad));

  List<int> _rand(int n) { final r = Random.secure(); return List.generate(n, (_) => r.nextInt(256)); }

  Future<void> create(String pw) async {
    final salt = _rand(16), raw = _rand(32);
    db = {'salt': base64.encode(salt), 'it': _iters, 'wrap': await _seal(await _kek(pw, salt, _iters), raw, 'vk'), 'recs': {}};
    await _persist();
    _vk = SecretKey(raw);
    recs = [];
    await audit('Vault created');
  }

  Future<Duration?> lockedFor() async {
    final f = await _st.read(key: 'fail');
    if (f == null) return null;
    final until = jsonDecode(f)['until'] as int;
    final left = until - DateTime.now().millisecondsSinceEpoch;
    return left > 0 ? Duration(milliseconds: left) : null;
  }

  Future<List<int>> _reauth(String pw) async =>
      _open(await _kek(pw, base64.decode(db!['salt']), db!['it']), db!['wrap'], 'vk');

  Future<String?> unlock(String pw) async {
    final wait = await lockedFor();
    if (wait != null) return 'Too many attempts. Wait ${wait.inSeconds + 1}s.';
    try {
      final raw = await _reauth(pw);
      final k = SecretKey(raw);
      final out = <Map<String, dynamic>>[];
      for (final e in (db!['recs'] as Map).entries) {
        out.add({'id': e.key, ...jsonDecode(utf8.decode(await _open(k, e.value, e.key)))});
      }
      _vk = k; recs = out;
      await _st.delete(key: 'fail');
      await audit('Vault opened');
      return null;
    } catch (_) {
      final f = await _st.read(key: 'fail');
      final n = (f == null ? 0 : jsonDecode(f)['n'] as int) + 1;
      final ms = n >= 3 ? min(pow(2, n - 3).toInt() * 5000, 600000) : 0;
      await _st.write(key: 'fail', value: jsonEncode({'n': n, 'until': DateTime.now().millisecondsSinceEpoch + ms}));
      await audit('Unlock failed', ok: false);
      return 'Could not unlock. Check your master passphrase.';
    }
  }

  void lock(String why) { _vk = null; recs = []; audit(why); }

  Future<void> saveRec(Map<String, dynamic> r) async {
    final id = r['id'] as String;
    final body = Map<String, dynamic>.from(r)..remove('id');
    (db!['recs'] as Map)[id] = await _seal(_vk!, utf8.encode(jsonEncode(body)), id);
    final i = recs.indexWhere((x) => x['id'] == id);
    i < 0 ? recs.add(r) : recs[i] = r;
    await _persist();
    await audit('Record saved');
  }

  Future<void> deleteRec(String id) async {
    (db!['recs'] as Map).remove(id);
    recs.removeWhere((x) => x['id'] == id);
    await _persist();
    await audit('Record deleted');
  }

  Future<bool> changePw(String oldPw, String newPw) async {
    try {
      final raw = await _reauth(oldPw);
      final salt = _rand(16);
      db!['salt'] = base64.encode(salt);
      db!['it'] = _iters;
      db!['wrap'] = await _seal(await _kek(newPw, salt, _iters), raw, 'vk'); // only the key wrapper changes
      await _persist();
      await audit('Master passphrase changed');
      return true;
    } catch (_) { return false; }
  }

  Future<String?> exportEncrypted(String pw) async {
    try { await _reauth(pw); await audit('Encrypted export'); return jsonEncode(db); } catch (_) { return null; }
  }

  String newId() => base64Url.encode(_rand(9));
}

// ------------------------------------------------------------------- app
class StrongroomApp extends StatelessWidget {
  const StrongroomApp({super.key});
  @override
  Widget build(BuildContext c) {
    ThemeData t(Brightness b) => ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF9A6F14), brightness: b, surface: b == Brightness.dark ? const Color(0xFF172630) : const Color(0xFFF7F9F9)),
        scaffoldBackgroundColor: b == Brightness.dark ? const Color(0xFF0F1A20) : const Color(0xFFE6ECEF),
        inputDecorationTheme: const InputDecorationTheme(border: OutlineInputBorder()));
    return MaterialApp(title: 'Strongroom', theme: t(Brightness.light), darkTheme: t(Brightness.dark), home: const Gate());
  }
}

class Gate extends StatefulWidget { const Gate({super.key}); @override State<Gate> createState() => _GateState(); }

class _GateState extends State<Gate> with WidgetsBindingObserver {
  final v = Vault();
  bool ready = false, hidden = false;
  Timer? idle, clip;

  @override
  void initState() { super.initState(); WidgetsBinding.instance.addObserver(this); v.load().then((_) => setState(() => ready = true)); }
  @override
  void dispose() { WidgetsBinding.instance.removeObserver(this); super.dispose(); }

  @override
  void didChangeAppLifecycleState(AppLifecycleState s) {
    if (!v.unlocked) return;
    if (s == AppLifecycleState.resumed) { setState(() => hidden = false); return; }
    setState(() => hidden = true); // hide content in app switcher
    if (s == AppLifecycleState.paused && (v.cfg['lock'] as int) == 0) doLock('Locked on background');
  }

  void arm() {
    idle?.cancel();
    final m = v.cfg['lock'] as int;
    if (v.unlocked && m > 0) idle = Timer(Duration(minutes: m), () => doLock('Auto-locked'));
  }

  void doLock(String why) { idle?.cancel(); v.lock(why); if (mounted) { Navigator.of(context).popUntil((r) => r.isFirst); setState(() {}); } }

  void copy(String s) {
    Clipboard.setData(ClipboardData(text: s));
    clip?.cancel();
    final sec = v.cfg['clip'] as int;
    clip = Timer(Duration(seconds: sec), () => Clipboard.setData(const ClipboardData(text: '')));
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Copied. Clears in $sec seconds.')));
  }

  @override
  Widget build(BuildContext c) {
    if (!ready) return const Scaffold(body: Center(child: CircularProgressIndicator()));
    return Listener(
      onPointerDown: (_) => arm(),
      child: Stack(children: [
        v.db == null ? AuthScreen(v: v, setup: true, done: () { arm(); setState(() {}); })
            : !v.unlocked ? AuthScreen(v: v, setup: false, done: () { arm(); setState(() {}); })
            : ListScreen(v: v, copy: copy, lock: doLock, refresh: () => setState(() {})),
        if (hidden) Positioned.fill(child: Container(color: Theme.of(c).scaffoldBackgroundColor, child: const Center(child: Icon(Icons.lock, size: 48)))),
      ]),
    );
  }
}

class AuthScreen extends StatefulWidget {
  final Vault v; final bool setup; final VoidCallback done;
  const AuthScreen({super.key, required this.v, required this.setup, required this.done});
  @override State<AuthScreen> createState() => _AuthState();
}

class _AuthState extends State<AuthScreen> {
  final p = TextEditingController(), p2 = TextEditingController();
  String err = ''; bool busy = false;

  Future<void> go() async {
    if (widget.setup) {
      if (p.text.length < 12) return setState(() => err = 'Use at least 12 characters. A phrase of several words works well.');
      if (p.text != p2.text) return setState(() => err = 'The passphrases do not match.');
    }
    setState(() { busy = true; err = ''; });
    String? e;
    if (widget.setup) { await widget.v.create(p.text); } else { e = await widget.v.unlock(p.text); }
    if (!mounted) return;
    p.clear();
    setState(() { busy = false; err = e ?? ''; });
    if (e == null) widget.done();
  }

  @override
  Widget build(BuildContext c) => Scaffold(
      body: SafeArea(child: ListView(padding: const EdgeInsets.all(20), children: [
        Text(widget.setup ? 'Strongroom' : 'Vault locked', style: Theme.of(c).textTheme.displaySmall),
        const SizedBox(height: 8),
        Text(widget.setup
            ? 'Create your master passphrase. Data is encrypted with AES-256-GCM before it is stored. A forgotten passphrase cannot be recovered, so keep a written copy somewhere safe. No system is unhackable; this design slows attackers and limits damage.'
            : 'Failed attempts add growing delays.'),
        const SizedBox(height: 16),
        TextField(controller: p, obscureText: true, enableSuggestions: false, autocorrect: false, decoration: const InputDecoration(labelText: 'Master passphrase')),
        if (widget.setup) ...[const SizedBox(height: 12), TextField(controller: p2, obscureText: true, decoration: const InputDecoration(labelText: 'Repeat passphrase'))],
        if (err.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 8), child: Text(err, style: TextStyle(color: Theme.of(c).colorScheme.error))),
        const SizedBox(height: 16),
        FilledButton(onPressed: busy ? null : go, child: Text(busy ? 'Working…' : widget.setup ? 'Create vault' : 'Unlock')),
      ])));
}

class ListScreen extends StatefulWidget {
  final Vault v; final void Function(String) copy; final void Function(String) lock; final VoidCallback refresh;
  const ListScreen({super.key, required this.v, required this.copy, required this.lock, required this.refresh});
  @override State<ListScreen> createState() => _ListState();
}

class _ListState extends State<ListScreen> {
  String q = '';
  Future<void> open(Widget w) async { await Navigator.push(context, MaterialPageRoute(builder: (_) => w)); setState(() {}); }

  @override
  Widget build(BuildContext c) {
    final v = widget.v;
    final f = v.recs.where((r) => '${r['title']} ${r['type']} ${r['tags']}'.toLowerCase().contains(q.toLowerCase())).toList(); // search only over unlocked in-memory data
    return Scaffold(
      appBar: AppBar(title: const Text('Vault'), actions: [
        IconButton(icon: const Icon(Icons.shield_outlined), tooltip: 'Security', onPressed: () => open(SecurityScreen(v: v, lock: widget.lock))),
        IconButton(icon: const Icon(Icons.lock), tooltip: 'Lock', onPressed: () => widget.lock('Vault locked manually')),
      ]),
      floatingActionButton: FloatingActionButton.extended(icon: const Icon(Icons.add), label: const Text('Add record'), onPressed: () async {
        final t = await showModalBottomSheet<String>(context: c, builder: (_) => ListView(children: [for (final k in kTypes.keys) ListTile(title: Text(k), onTap: () => Navigator.pop(c, k))]));
        if (t == null) return;
        open(EditScreen(v: v, rec: {'id': v.newId(), 'type': t, 'title': '', 'tags': '', 'fields': [for (final x in kTypes[t]!) {'l': x[0], 's': x[1], 'v': ''}]}));
      }),
      body: Column(children: [
        Padding(padding: const EdgeInsets.all(12), child: TextField(decoration: const InputDecoration(prefixIcon: Icon(Icons.search), hintText: 'Search this vault'), onChanged: (s) => setState(() => q = s))),
        Expanded(child: f.isEmpty
            ? Center(child: Text(v.recs.isEmpty ? 'The vault is empty. Add your first record.' : 'No records match.'))
            : ListView(children: [for (final r in f) ListTile(title: Text(r['title'] == '' ? '(untitled)' : r['title']), trailing: Chip(label: Text(r['type'])), onTap: () => open(ViewScreen(v: v, rec: r, copy: widget.copy)))])),
      ]));
  }
}

class ViewScreen extends StatefulWidget {
  final Vault v; final Map<String, dynamic> rec; final void Function(String) copy;
  const ViewScreen({super.key, required this.v, required this.rec, required this.copy});
  @override State<ViewScreen> createState() => _ViewState();
}

class _ViewState extends State<ViewScreen> {
  final shown = <int>{};
  @override
  Widget build(BuildContext c) {
    final r = widget.rec;
    final fs = (r['fields'] as List).where((f) => f['v'] != '').toList();
    return Scaffold(
      appBar: AppBar(title: Text(r['title'] == '' ? '(untitled)' : r['title']), actions: [
        IconButton(icon: const Icon(Icons.edit), onPressed: () async { await Navigator.push(c, MaterialPageRoute(builder: (_) => EditScreen(v: widget.v, rec: r))); setState(() {}); }),
        IconButton(icon: const Icon(Icons.delete_outline), onPressed: () async {
          final ok = await showDialog<bool>(context: c, builder: (_) => AlertDialog(title: const Text('Delete record?'), content: const Text('This cannot be undone.'), actions: [TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')), TextButton(onPressed: () => Navigator.pop(c, true), child: const Text('Delete'))]));
          if (ok == true) { await widget.v.deleteRec(r['id']); if (c.mounted) Navigator.pop(c); }
        }),
      ]),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Text('${r['type']}${r['tags'] == '' ? '' : ' · ${r['tags']}'}'),
        for (var i = 0; i < fs.length; i++) ListTile(
          title: Text(fs[i]['l']),
          subtitle: Text(fs[i]['s'] == true && !shown.contains(i) ? '••••••••••••' : fs[i]['v'], style: const TextStyle(fontFamily: 'monospace')),
          trailing: Row(mainAxisSize: MainAxisSize.min, children: [
            if (fs[i]['s'] == true) IconButton(icon: Icon(shown.contains(i) ? Icons.visibility_off : Icons.visibility), onPressed: () {
              setState(() => shown.contains(i) ? shown.remove(i) : shown.add(i));
              if (shown.contains(i)) Timer(const Duration(seconds: 15), () { if (mounted) setState(() => shown.remove(i)); });
            }),
            IconButton(icon: const Icon(Icons.copy), onPressed: () => widget.copy(fs[i]['v'])),
          ])),
      ]));
  }
}

class EditScreen extends StatefulWidget {
  final Vault v; final Map<String, dynamic> rec;
  const EditScreen({super.key, required this.v, required this.rec});
  @override State<EditScreen> createState() => _EditState();
}

class _EditState extends State<EditScreen> {
  late final title = TextEditingController(text: widget.rec['title']);
  late final tags = TextEditingController(text: widget.rec['tags']);
  late final List<Map<String, dynamic>> fs = [for (final f in widget.rec['fields']) {'l': TextEditingController(text: f['l']), 'v': TextEditingController(text: f['v']), 's': f['s']}];

  @override
  Widget build(BuildContext c) => Scaffold(
      appBar: AppBar(title: Text('${widget.rec['type']} record')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        TextField(controller: title, decoration: const InputDecoration(labelText: 'Title')),
        const SizedBox(height: 12),
        TextField(controller: tags, decoration: const InputDecoration(labelText: 'Tags, comma separated')),
        for (final f in fs) Card(child: Padding(padding: const EdgeInsets.all(12), child: Column(children: [
          TextField(controller: f['l'], readOnly: widget.rec['type'] != 'Custom' && !(f['custom'] ?? false), decoration: const InputDecoration(labelText: 'Field name')),
          const SizedBox(height: 8),
          TextField(controller: f['v'], obscureText: f['s'], maxLines: f['s'] ? 1 : null, autocorrect: false, decoration: const InputDecoration(labelText: 'Value')),
          SwitchListTile(title: const Text('Hide by default'), value: f['s'], onChanged: (x) => setState(() => f['s'] = x)),
        ]))),
        Row(children: [
          OutlinedButton(onPressed: () => setState(() => fs.add({'l': TextEditingController(), 'v': TextEditingController(), 's': false, 'custom': true})), child: const Text('Add field')),
          const SizedBox(width: 12),
          FilledButton(onPressed: () async {
            await widget.v.saveRec({'id': widget.rec['id'], 'type': widget.rec['type'], 'title': title.text.trim(), 'tags': tags.text, 'updated': DateTime.now().toIso8601String(),
              'fields': [for (final f in fs) {'l': f['l'].text, 's': f['s'], 'v': f['v'].text}]});
            widget.rec..['title'] = title.text.trim()..['tags'] = tags.text;
            if (c.mounted) Navigator.pop(c);
          }, child: const Text('Save encrypted')),
        ]),
      ]));
}

class SecurityScreen extends StatefulWidget {
  final Vault v; final void Function(String) lock;
  const SecurityScreen({super.key, required this.v, required this.lock});
  @override State<SecurityScreen> createState() => _SecState();
}

class _SecState extends State<SecurityScreen> {
  final cur = TextEditingController(), nw = TextEditingController();
  String msg = '';

  Future<String?> ask(String label) {
    final t = TextEditingController();
    return showDialog<String>(context: context, builder: (c) => AlertDialog(title: Text(label), content: TextField(controller: t, obscureText: true), actions: [TextButton(onPressed: () => Navigator.pop(c), child: const Text('Cancel')), TextButton(onPressed: () => Navigator.pop(c, t.text), child: const Text('Continue'))]));
  }

  @override
  Widget build(BuildContext c) {
    final v = widget.v;
    final fails = v.log.where((l) => l['ok'] == false).length;
    return Scaffold(appBar: AppBar(title: const Text('Security')), body: ListView(padding: const EdgeInsets.all(16), children: [
      Text('Records: ${v.recs.length} · Failed unlock attempts logged: $fails'),
      const SizedBox(height: 12),
      DropdownButtonFormField<int>(value: v.cfg['lock'], decoration: const InputDecoration(labelText: 'Auto-lock'), items: const [DropdownMenuItem(value: 0, child: Text('On background')), DropdownMenuItem(value: 1, child: Text('1 minute')), DropdownMenuItem(value: 5, child: Text('5 minutes')), DropdownMenuItem(value: 15, child: Text('15 minutes'))], onChanged: (x) { v.cfg['lock'] = x; v.saveCfg(); }),
      const SizedBox(height: 12),
      DropdownButtonFormField<int>(value: v.cfg['clip'], decoration: const InputDecoration(labelText: 'Clear clipboard after'), items: const [DropdownMenuItem(value: 30, child: Text('30 seconds')), DropdownMenuItem(value: 60, child: Text('60 seconds')), DropdownMenuItem(value: 120, child: Text('2 minutes'))], onChanged: (x) { v.cfg['clip'] = x; v.saveCfg(); }),
      const SizedBox(height: 12),
      FilledButton.tonal(onPressed: () { Navigator.pop(c); widget.lock('Emergency lock'); }, child: const Text('Emergency lock')),
      const Divider(height: 32),
      Text('Change master passphrase', style: Theme.of(c).textTheme.titleMedium),
      TextField(controller: cur, obscureText: true, decoration: const InputDecoration(labelText: 'Current passphrase')),
      const SizedBox(height: 8),
      TextField(controller: nw, obscureText: true, decoration: const InputDecoration(labelText: 'New passphrase (12+ characters)')),
      const SizedBox(height: 8),
      FilledButton(onPressed: () async {
        if (nw.text.length < 12) return setState(() => msg = 'Use at least 12 characters.');
        final ok = await v.changePw(cur.text, nw.text);
        setState(() => msg = ok ? 'Changed. Only the key wrapper was re-encrypted.' : 'Current passphrase is wrong.');
        if (ok) { cur.clear(); nw.clear(); }
      }, child: const Text('Change passphrase')),
      if (msg.isNotEmpty) Text(msg),
      const Divider(height: 32),
      Text('Encrypted backup', style: Theme.of(c).textTheme.titleMedium),
      const Text('Export stays encrypted with your master passphrase, but any extra copy is extra risk. The backup is copied to your clipboard, which clears on your clipboard timer.'),
      OutlinedButton(onPressed: () async {
        final pw = await ask('Re-enter master passphrase'); if (pw == null) return;
        final out = await v.exportEncrypted(pw);
        if (out == null) return setState(() => msg = 'Wrong passphrase.');
        await Clipboard.setData(ClipboardData(text: out));
        Timer(Duration(seconds: v.cfg['clip']), () => Clipboard.setData(const ClipboardData(text: '')));
        setState(() => msg = 'Encrypted backup copied.');
      }, child: const Text('Export encrypted backup')),
      const Divider(height: 32),
      Text('Activity log', style: Theme.of(c).textTheme.titleMedium),
      const Text('Events only, never secrets. IP logging needs a server.'),
      for (final l in v.log.take(25)) Text('${l['ok'] == false ? 'FAILED · ' : ''}${l['e']} · ${l['t']}', style: Theme.of(c).textTheme.bodySmall),
    ]));
  }
}
