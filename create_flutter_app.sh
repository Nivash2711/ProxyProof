#!/usr/bin/env bash
set -euo pipefail
flutter create --org com.proxyproof --project-name proxyproof_app --platforms android flutter_app_generated
cp flutter_app/pubspec.yaml flutter_app_generated/pubspec.yaml
cp flutter_app/lib/main.dart flutter_app_generated/lib/main.dart
mkdir -p flutter_app_generated/android/app/src/main/kotlin/com/proxyproof/proxyproof_app
cp flutter_app/android/app/src/main/kotlin/com/proxyproof/proxyproof_app/MainActivity.kt flutter_app_generated/android/app/src/main/kotlin/com/proxyproof/proxyproof_app/MainActivity.kt
cp flutter_app/android/app/src/main/AndroidManifest.xml flutter_app_generated/android/app/src/main/AndroidManifest.xml
cd flutter_app_generated
flutter pub get
printf '\nProject ready. Run: flutter run\n'
