```md
# mini-sync — AGENTS.md

mini-sync는 **Standalone WM/Compositor(Sway/Hyprland 등) 사용자**를 위한 **PC ↔ Android** “딱 필요한 것만” 도구다.

- 핵심 기능 2개만: **클립보드 동기화**, **파일 공유**
- 목표 UX: KDE Connect 같은 “데스크톱 통합”이 아니라, **의존성 최소 + CLI/간단 UI + 파일관리자 커스텀 액션**으로 빠르게 실사용 가능하게 만들기
- 금지사항: Plasma/Qt/KDE Frameworks에 기대지 않기(“KDE 스택 깔려오는 문제” 회피)

---

## 1) 제품 정의

### 1.1 MVP(반드시)
1) **페어링**
   - 같은 LAN에서 기기 발견
   - QR 코드 또는 짧은 코드로 페어링
   - 페어링된 기기 목록 관리(추가/삭제/상태)

2) **파일 공유**
   - PC → Android: 파일/폴더(폴더는 zip 처리 가능) 전송
   - Android → PC: Android Share Intent로 전송(파일 1개부터 시작해도 OK)
   - 수신 시 저장 위치 지정(최소한 기본 폴더 제공)

3) **클립보드 동기화(텍스트 우선)**
   - PC → Android, Android → PC 모두
   - “자동 동기화(Watch)” 옵션 + “수동 Push” 옵션 제공
   - 충돌 정책: **Last-write-wins** (timestamp + source device id)

4) **보안**
   - 페어링 이후 모든 통신은 **암호화 + 인증**
   - 동일 LAN이라도 “그냥 평문” 금지

### 1.2 Non-goals(지금은 안 함)
- 화면 미러링/원격 입력, SMS 연동, 전화 알림 연동
- GNOME/KDE 수준의 파일관리자 확장(나중에 가능)
- 이미지/바이너리 클립보드 동기화(1차 MVP에서는 텍스트만)

---

## 2) 플랫폼/기술 선택(권장)

### 2.1 Desktop(Linux) — 권장: Rust
- 바이너리 1~2개로 끝내기: `mini-sync`(CLI), `mini-syncd`(daemon)
- Wayland 클립보드:
  - MVP는 **wl-clipboard**(`wl-copy`, `wl-paste`) 호출로 구현 (가장 단순/범용)
  - 추후 네이티브 Wayland 프로토콜 직접 연동은 옵션

### 2.2 Android — 권장: Kotlin + Jetpack Compose
- 백그라운드 제약 대응:
  - 클립보드 자동 감지는 “항상”이 아니라
    - **앱 포그라운드 시 즉시**
    - **사용자 토글 시 Foreground service(상단 알림)**로 제한적 지원

---

## 3) 아키텍처(간단/견고)

### 3.1 구성요소
- Desktop
  - `mini-syncd`: 백그라운드 데몬(네트워크, 페어링, 수신, 클립보드 watch)
  - `mini-sync`: CLI(페어링 시작/파일 전송/상태 확인)
- Android
  - 앱(페어링/수신 저장/클립보드/Share Intent)
- 공통
  - 메시지 스키마(가능하면 `proto/`에 JSON schema 또는 protobuf 정의)

### 3.2 네트워크 플로우(권장)
- **Discovery**: mDNS(zeroconf)
  - 서비스: `_minisync._tcp`
  - TXT: `device_id`, `device_name`, `capabilities`(clipboard,file)
- **Control Channel**: TCP 1개(고정 포트 or 발견된 포트)
- **File Transfer**: “오퍼(offer) + pull” 방식 권장
  - 작은 파일은 바로 전송해도 되지만, 기본은:
    1) Sender가 `FILE_OFFER`(메타데이터 + 단기 토큰) 전송
    2) Receiver가 승인 후 `GET /file/<id>?token=...`로 다운로드
  - 장점: 큰 파일 전송이 단순해지고, 재시도/중단 복구가 쉬움

---

## 4) 보안 설계(최소 요건)

### 4.1 페어링(권장 UX)
- Desktop에서 `mini-sync pair` 실행 → QR 표시
- QR 내용:
  - `device_id`, `ip:port`
  - Sender의 장기 공개키(또는 fingerprint)
  - **1회용 pairing token**(짧은 TTL: 2~5분)
  - 사람이 확인할 **6자리 코드**(MITM 방지 보조)

### 4.2 암호화/인증(권장 구현 1안)
- 장기 키: Ed25519 또는 X25519 (라이브러리 표준 선택)
- 세션: Noise/libsodium box 계열(검증된 구현 사용)
- 메시지 프레이밍:
  - `header(version, msg_type, nonce, sender_id, ts)`
  - `ciphertext(payload)`
- 페어링 이후에는 **서로의 장기 공개키를 pinning**하고,
  - 이후 연결은 “이 키로 서명/암호화된 상대만 허용”

> 주의: “직접 암호 설계” 금지. 표준 라이브러리/프로토콜 사용.

---

## 5) 메시지 타입(초기 최소)

공통 필드:
- `version`
- `msg_id`(UUID)
- `sender_device_id`
- `timestamp_ms`

### 5.1 Control
- `HELLO` (capabilities, device_name)
- `PAIR_REQUEST` (token, code, pubkey)
- `PAIR_ACCEPT` (code_confirm, pubkey)
- `PAIR_REJECT`
- `PING` / `PONG`

### 5.2 Clipboard
- `CLIP_PUSH`
  - `content_type`: `text/plain` (MVP 고정)
  - `text`: string
  - `clip_id`: UUID
- `CLIP_ACK` (optional)

### 5.3 File
- `FILE_OFFER`
  - `offer_id`: UUID
  - `items`: [{name, size, sha256}]
  - `download_url` 또는 `endpoint + token`
- `FILE_ACCEPT` / `FILE_REJECT`
- `FILE_DONE` / `FILE_ERROR`

---

## 6) Desktop UX 스펙

### 6.1 CLI 명령(최소)
- `mini-sync status`
- `mini-sync devices`
- `mini-sync pair` (QR 출력: ANSI/터미널 또는 이미지 파일 생성)
- `mini-sync unpair <device>`
- `mini-sync send <device> <path...>`
- `mini-sync clipboard push <device>` (현재 클립보드 1회 전송)
- `mini-sync clipboard watch <device>` (자동 감지/전송 시작)
- `mini-sync config` (경로 출력 정도만)

### 6.2 데몬
- user systemd 서비스 권장:
  - `~/.config/systemd/user/mini-sync.service`
  - `ExecStart=/usr/bin/mini-syncd`
- 설정 파일(권장: TOML)
  - `~/.config/mini-sync/config.toml`
  - 예:
    - `listen_port`
    - `download_dir`
    - `clipboard.watch = true/false`
    - `paired_devices = [...]`

### 6.3 파일관리자 연동(문서 제공)
- Nautilus/Thunar는 확장보다 **커스텀 액션 레시피**를 README에 제공
- 예: `mini-sync send <device> %F`

---

## 7) Android UX 스펙

- 페어링: QR 스캔 → 코드 확인 → 완료
- 파일 수신: 알림/화면에서 수락 → 저장 위치 선택(가능하면 SAF: Storage Access Framework)
- 파일 송신: Share Intent로 “mini-sync로 보내기” 제공
- 클립보드:
  - 수동: “Send clipboard to PC”
  - 자동: 토글 시 Foreground service(상단 알림)로 동작

---

## 8) 저장/로깅

- Desktop:
  - 페어링 정보(상대 공개키, 이름, 마지막 접속) 저장
  - 로그: `~/.local/state/mini-sync/logs/` 또는 stdout + journald
- Android:
  - 키는 Keystore에 저장
  - 마지막 동기화 상태만 간단히 저장

---

## 9) 테스트(최소)

- 단위 테스트
  - 메시지 직렬화/역직렬화
  - 암호화/복호화 라운드트립
  - offer 토큰 TTL/검증
- 통합 테스트(가능하면)
  - Desktop 데몬 2개를 띄워 페어링/클립/파일 오퍼까지 시뮬레이션

---

## 10) 마일스톤 / 구현 순서(중요)

### M0: Skeleton
- repo 구조 생성(`desktop/`, `android/`, `proto/`)
- Desktop: `mini-sync status` / `mini-syncd --version`

### M1: Discovery + Pairing
- mDNS 광고/탐색
- QR 기반 페어링
- paired device 저장/삭제

### M2: Clipboard (text)
- Desktop: `clipboard push`, `clipboard watch`(wl-paste 기반)
- Android: 수동 전송 + 포그라운드 시 감지

### M3: File Transfer
- PC→Android: offer + pull
- Android→PC: Share Intent → 업로드(또는 offer + pull)

### M4: Hardening
- 재연결 안정화, 타임아웃/재시도
- 충돌 정책 고정, 로그/진단 개선

---

## 11) Definition of Done(MVP)

- Fedora(Sway/Hyprland) 환경에서:
  - 페어링 성공
  - 텍스트 클립보드 양방향 동기화(수동/자동 중 하나 이상)
  - 파일 PC→Android 전송 성공
  - Android→PC 전송(Share Intent) 성공
  - 모든 통신이 암호화/인증됨
- KDE/Qt/KF 의존성 없이 동작(Desktop는 wl-clipboard 정도는 허용)

---

## 12) 에이전트 작업 가이드(필독)

- “멋진 기능”보다 **M1~M3 완주**가 우선.
- 보안은 “대충” 금지. 라이브러리 기반으로 구현.
- Android 클립보드는 시스템 제약이 있으니:
  - **수동 버튼 + 선택적 Foreground service**로 MVP를 완성하고,
  - “항상 자동”은 후순위.
- 코드 생성 도구는 적극 사용하되,
  - 암호/인증/키관리 로직은 사람이 설계 의도를 검토하고 진행할 것.

끝.
```
