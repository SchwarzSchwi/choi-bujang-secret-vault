# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, [...]

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니[...]
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 [...]

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `p[...]

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가[...]

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack[...]

## 2단계: 자료를 코드 밖으로 옮깁니다

### 변경 사항

- Supabase `notes` 테이블 초기화 (`init-notes-table.sql`)
- 공개 `/data.json`에서 가상 메모 제거 (배열 비움)
- `/api/notes` 서버 함수 추가 (Supabase에서 메모 읽기)
- 화면은 정적 JSON 대신 서버 함수에서 메모를 가져옴

### 현재 설정

- `SUPABASE_URL`: Supabase 프로젝트 URL (환경변수)
- `SUPABASE_SECRET_KEY`: 서버 전용 비밀 키 (환경변수, 절대 노출 금지)
- `/api/notes` 응답: `{ "notes": [...] }`

### 현재 약점

**공개 주소**: `/api/notes` 함수는 공개 Vercel 도메인에 있어서 누구나 호출할 수 있습니다. 3단계에서 인증을 추가하기 전까지 서버 환경변수 보호가 주요 보안 관심사입니다. 함수는 키를 응답이나 로그에 절대 넣지 않습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름[...]

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bu[...]
