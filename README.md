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
GitHub 저장소 공개는 웹 앱 배포가 아닙니다. HTTPS 운영 배포는 미실행입니다.
