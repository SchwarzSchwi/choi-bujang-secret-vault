# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 개인키, 서버 비밀은 절대 이 저장소에 넣지 마세요.

## 가상 메모 노출 검사

학생은 다음 절차로 현재 배포와 GitHub 최신 코드에서 가상 메모가 노출되지 않았는지 확인합니다.

### 확인할 문장

프로젝트 `public/data.json`, `src/api/notes.js`, 배포 공개 함수 `/api/notes`에서 다음 네 문장을 찾습니다:
- `"메모 1: 방어전 출발 자료"`
- `"메모 2: 방어전 출발 자료"`
- `"메모 3: 방어전 출발 자료"`
- `"메모 4: 방어전 출발 자료"`

### GitHub 최신 파일 검색 (현재 main 브랜치)

1. 저장소 → **Code** 탭
2. 오른쪽 위 **Search this repository** (또는 `/` 단축키)
3. 검색어: `방어전 출발 자료`
4. 결과 기록: 찾은 파일 경로와 줄 번호 / 찾지 못함

### 배포된 `/data.json` 검색 (현재 Vercel 주소)

1. 배포 주소 + `/data.json` 방문 (예: `https://myapp.vercel.app/data.json`)
2. 브라우저 **페이지 소스 보기** (Ctrl+U / Cmd+U)
3. 페이지 내 검색 (Ctrl+F / Cmd+F): `방어전 출발 자료`
4. 결과 기록: 찾은 횟수 / 찾지 못함

### 배포된 `/api/notes` 검색 (현재 Vercel 주소)

1. 배포 주소 + `/api/notes` 방문 (예: `https://myapp.vercel.app/api/notes`)
2. 브라우저 **페이지 소스 보기**
3. 페이지 내 검색: `방어전 출발 자료`
4. 결과 기록: 찾은 횟수 / 찾지 못함

### 중요 제약

- **옛 공개 커밋 (이전 버전)**: GitHub 커밋 내역을 뒤지거나 저장소 공개 URL의 이전 버전에서 가상 메모가 보이는 것은 **이번 단계에서 검사하지 않습니다**. 옛 커밋이 존재하는 한 과거 노출은 완전히 해소됐다고 쓰지 마세요.
- **옛 배포**: Vercel의 이전 배포 URL이나 스냅샷 서비스에서 접근 가능하다면 그 역시 이번 검사 범위 밖입니다.
- **현재 상태만 기록**: 이번 점검은 **지금 GitHub main과 현재 배포 Vercel 주소**에만 적용됩니다.

### 검사 결과 예시

```
✓ GitHub main 브랜치: 가상 메모 문장 없음
✓ Vercel /data.json: 가상 메모 문장 없음
✓ Vercel /api/notes: 가상 메모 문장 없음
⚠ 공개 API의 남은 약점:
   - 인증 없이 /api/notes 호출 가능
   - 인증 없이 /data.json 다운로드 가능
```

---

## 2단계: 가상 메모를 Supabase API로 보호

2단계부터 화면은 `/api/notes` 서버 함수를 통해 Supabase에서 네 건의 가상 메모를 읽습니다. 서버 함수는 다음 환경변수를 읽습니다:

- `SUPABASE_URL`: Supabase 프로젝트 URL
- `SUPABASE_SECRET_KEY`: 서버 전용 API 키

**보안 약점**: 현재 `/api/notes`는 인증과 접근 제어가 없는 공개 함수입니다. 누구나 호출할 수 있습니다. 다음 단계에서 로그인 요구와 거절 규칙을 추가합니다.

환경변수는 Vercel 배포 설정의 **비밀 입력란**에만 넣고, 코드나 로그에 값을 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 목표입니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/data.json`과 `aleph.config.json`을 만듭니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정값을 자동으로 써줍니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 학생의 자기 점검이며, 심판의 결과 보고가 아닙니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름은 유지하되, 실제 메모는 Supabase에서만 읽습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 정의돼 있습니다.
