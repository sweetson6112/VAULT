# Strongroom (Flutter)
    flutter create . --project-name strongroom   # generates android/ios folders (keeps lib/ and pubspec.yaml)
    flutter pub get && flutter run
Android: set minSdkVersion 23+ in android/app/build.gradle (flutter_secure_storage).
Android: in MainActivity add getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE) to block screenshots.
