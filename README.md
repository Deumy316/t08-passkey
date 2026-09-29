# T08 패스키 자기소개 페이지

공개 자기소개와 Flask + SQLite + WebAuthn 기반 비공개 공간입니다.
패스키 로그인, 계정별 가상 메모, 재인증 후 패스키 추가·삭제를 제공합니다.

## Windows PowerShell 실행

```powershell
Set-Location C:\work\aleph\t08-passkey
py -3 -m venv .venv
py -3 -m pip --python .\.venv\Scripts\python.exe install -r requirements.txt
$env:APP_ENV = "development"
$env:APP_ORIGIN = "http://localhost:5008"
$env:RP_ID = "localhost"
.\.venv\Scripts\python.exe app.py
```

이미 가상환경과 의존성이 설치되어 있으면 설치 두 줄은 생략합니다.
브라우저: **http://localhost:5008**. 종료: Ctrl+C.
기존 localhost:5000 앱과 별도로 실행합니다.

`.env.example`은 값 없는 환경변수 안내이며 자동으로 로드되지 않습니다.
실제 DB와 세션은 실행 시 `instance/`에 생성되고 Git에서 제외됩니다.
개인키는 인증기가 관리하며 서버에는 공개키를 저장합니다.

## 검증 상태

이전 소프트웨어 인증기 자동 검증 결과와 제한은 [T08-제출.md](T08-제출.md)에 있습니다.
이번 GitHub 업로드 작업에서는 전체 테스트를 반복하지 않았습니다.
사용자 PC는 Bluetooth를 지원하지 않고 별도 USB 보안 키가 없어,
실제 기기의 예비 키 등록·삭제·삭제 전후 로그인 검사는 보류 및 **미확인**입니다.
중복 등록 방지와 사용자 검증은 유지합니다. 모든 패스키 분실 시 복구할 수 없습니다.
사용자가 알려 준 배포 주소는 https://oliver92391.pythonanywhere.com 입니다.
기기 연결 변경의 커밋·push 이력은 GitHub에서 확인합니다. 배포 서버 반영은 별도이며 아직 수행하지 않았습니다.

## 아이폰 / 다른 기기 패스키 연결 (Bluetooth 불필요)

PC와 아이폰이 각각 같은 HTTPS 사이트에 접속하는 승인 방식입니다.
아이폰이 PC의 localhost 주소에 접속하는 방식이 아닙니다.
PC의 첫 패스키가 **해당 배포 도메인의 demo-a**에 등록되어 있어야 합니다.
localhost에서만 등록한 패스키와 DB를 복사해도 배포 도메인 인증에 사용할 수 없습니다.

새 코드를 서버에 반영할 때는 T08 가상환경에서 `pip install -r requirements.txt`로
QR 의존성을 설치하고 T08 앱만 재시작합니다. 이 작업은 아직 수행하지 않았습니다.
`create_app()`이 기존 DB에 `device_links` 테이블만 추가합니다.
기존 계정·메모·패스키를 초기화하지 않습니다. DB는 기존 영구 경로를 유지하고 반영 전 백업하세요.
T07 서비스·DB·설정은 변경하지 않습니다.

운영 환경은 다음 값이어야 합니다(`.env` 자동 로드 없음):

```text
APP_ENV=production
APP_ORIGIN=https://oliver92391.pythonanywhere.com
RP_ID=oliver92391.pythonanywhere.com
```

버튼 순서:

1. **PC**: 해당 HTTPS 사이트에서 demo-a로 로그인 → **아이폰/다른 기기 패스키 연결** → Windows Hello로 재인증.
2. **PC**: 5분짜리 QR을 아이폰 카메라로 읽거나 **링크 복사**로 본인 아이폰에 전달. PC의 로그인 탭은 유지합니다.
3. **아이폰**: 로그아웃 상태의 Safari에서 링크 열기 → 연결 대상이 demo-a인지 확인 → 새 패스키 이름 입력 → **이 기기에 패스키 만들기** → 기기의 사용자 인증 수행.
4. **양쪽**: 아이폰과 PC에 표시되는 확인 코드가 정확히 같은지 직접 비교. 모르는 요청·코드 불일치는 PC의 **연결 취소 / 거절**을 누릅니다.
5. **PC**: **코드 일치 확인 후 본인 인증하여 승인** → 기존 Windows Hello로 다시 인증. 승인 전 아이폰 키는 로그인할 수 없습니다.
6. **아이폰**: 승인 안내 후 **홈으로 이동하여 패스키로 로그인** → 새 키로 로그인. PC 목록에서도 이름·등록일을 확인합니다. 삭제는 기존 재인증 후 삭제 기능을 사용합니다.

링크는 한 번 열린 새 기기 세션에 묶입니다. 아이폰 페이지 새로고침·세션 유실·5분 만료 시
PC에서 새 링크를 만드세요. PC 로그아웃 또는 새 연결 생성은 이전 요청을 무효화합니다.
기기에는 키가 만들어졌어도 취소·만료·네트워크 실패로 승인되지 않으면 서버 로그인에 사용할 수 없습니다.
이런 기기 저장소의 미승인 항목은 직접 정리해야 합니다.
연결 링크·QR은 본인 기기에만 전달하고 캡처·HAR·인증 요청 원문을 공개하지 마세요.

연결 토큰은 32바이트 난수이며 DB에는 SHA-256 해시만 저장합니다.
URL fragment를 사용하고 새 기기 페이지가 즉시 주소에서 제거합니다.
QR은 서버의 qrcode 라이브러리로 생성하며 외부 QR 서비스·리소스를 사용하지 않습니다.
등록 검증된 공개키는 대기 테이블에 두고, 생성 PC 세션과 해당 credential에 묶인
일회용 재인증 권한을 확인한 후 SQLite 트랜잭션으로 한 번만 활성화합니다.
기존 excludeCredentials와 사용자 검증 required는 유지됩니다.

집중 검증 명령(전체 테스트 아님):

```powershell
.\.venv\Scripts\python.exe test_device_links.py
```

소프트웨어 인증기 + 실제 WebAuthn 검증으로 3개 시나리오 통과:
정상 승인·새 키 로그인(200), 승인 전 로그인/메모 차단(401), 재인증 없는 승인(403),
다른 PC 세션 승인 차단(403), 만료·취소·링크/승인 재사용(409),
challenge 재사용·만료 및 origin/RP ID/UV 오류(400).
토큰·세션은 출력에서 가립니다. 실제 아이폰 Face ID·Safari UI·QR 스캔·새 키 삭제 검사는 **미확인**입니다.
