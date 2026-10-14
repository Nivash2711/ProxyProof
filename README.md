# ProxyProof — Flutter + Android BLE + FastAPI MVP

This is an Android-first Flutter client with a small Kotlin MethodChannel bridge for BLE advertise/scan, and a FastAPI + SQLite backend. It is a working MVP source bundle; it has not been compiled on a device in this environment.

## Features
- Login with organiser/student roles.
- Students are bound to the first Android device ID seen by the backend; other device IDs are rejected.
- Organiser creates a timed session; the organiser phone broadcasts a rotating HMAC token using a compact service UUID payload.
- Student taps Scan / mark attendance; the app scans for beacons and sends the payload to the server.
- Server validates token freshness, session activity, registered device, role and RSSI threshold; database unique constraint prevents duplicate marks.
- Live roster polling, manual add/remove, close session, CSV display/export, and student attendance history endpoint.
- Small web dashboard available at backend root `/`.

## Limitations and security
- Admin device-change requests can be listed and approved through `GET /api/admin/device-requests` and `POST /api/admin/device-approval` using the admin demo account; the Flutter app does not yet have an admin approval screen.
- The MVP requires the student to tap Scan; reliable background auto-attendance is not implemented.
- Use two physical Android phones. BLE advertising/scanning may not work as expected on emulators.
- RSSI is only a rough proximity estimate, not proof of physical presence. Rotating tokens deter simple replay but cannot stop live relay attacks.
- The BLE service UUID payload packs marker + 32-bit session ID + 64-bit HMAC token into 128 bits to fit legacy BLE advertising limits. Token validity is five seconds with the previous bucket also accepted. This is a demonstration protocol, not a cryptographic proximity proof.
- Device binding uses Android ID as an app-provided device identifier, not hardware-backed attestation. For stronger assurance use Android Keystore keypairs and server-verified signatures.
- Local HTTP is enabled only for development. Do not use real student data until HTTPS, secure secret management, rate limits, audit logs, admin/device approval UI, roster-based percentage calculations, and a security review are added.
- CSV is shown as selectable text in the app rather than written directly to Downloads.

## Requirements
- Python 3.10+
- Flutter stable and Android Studio / Android SDK
- Two Android phones for BLE end-to-end testing

## 1. Start the backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
export PROXYPROOF_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```
Open `http://127.0.0.1:8000/docs` or the organiser dashboard at `http://127.0.0.1:8000`.

## 2. Generate the Flutter Android project
From this folder:
```bash
bash create_flutter_app.sh
cd flutter_app_generated
flutter doctor
flutter run
```
This script uses `flutter create` to generate the Gradle wrapper and platform scaffolding, then copies in the supplied Dart app, Android manifest and Kotlin BLE bridge.

## 3. Configure the backend URL
In `flutter_app_generated/lib/main.dart`, edit `Api.baseUrl`:
- Android emulator: `http://10.0.2.2:8000`
- Physical phone: `http://YOUR_COMPUTER_LAN_IP:8000`, e.g. `http://192.168.1.20:8000`

The phone and computer must be on the same trusted Wi-Fi network. Permit port 8000 through your local firewall. The manifest allows cleartext HTTP for local testing only.

## Demo accounts
- Organiser: `organiser` / `organiser123`
- Student: `student1` / `student123`
- Student 2: `student2` / `student123`
- Admin (device approvals via API docs): `admin` / `admin12345`

## End-to-end test
1. Start the backend and verify `/health` is not provided; instead open `/docs` or `/` to confirm the server is up.
2. Run the Flutter app on Phone A, set its backend URL, log in as organiser and tap **Start session**.
3. Accept Nearby devices permission and confirm the app reports broadcasting.
4. Run the app on Phone B, log in as `student1`, tap **Scan / mark attendance** and wait for the scan to finish.
5. Confirm the app reports attendance marked. Open the organiser session roster; it polls every four seconds.
6. Scan again; the server should report that attendance is already recorded rather than create a duplicate.
7. Test Student 2 on a third phone or after resetting the local database; each student account binds to its first device ID.
8. Use the roster + button to add by username, remove an attendance mark, and export CSV.
9. Close the session; the backend should reject any later attendance request.

## Database schema
SQLAlchemy creates SQLite `backend/proxyproof.db` on startup:
- `users(id, username, password_hash, role, device_id, device_change_pending)`
- `attendance_sessions(id, organiser_id, title, starts_at, ends_at, active)`
- `attendance(id, session_id, student_id, marked_at, rssi, source)` with unique `(session_id, student_id)`.

## Troubleshooting
- **Connection refused:** confirm backend is running, correct IP/port, and firewall permits traffic.
- **Permission error:** Android Settings → Apps → ProxyProof → Permissions → Nearby devices; on Android 11 or older also grant Location.
- **BLE advertising failed:** some phones do not support advertising, Bluetooth must be enabled, and the organiser app should remain foregrounded.
- **Token expired:** token rotates every five seconds; retry scan near the organiser.
- **Device is bound to another phone:** reset `backend/proxyproof.db` for a demo reset (deletes demo attendance) or implement/use the admin approval workflow before using real accounts.
