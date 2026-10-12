# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 실제 이름을 넣으면 안 됩니다.

## 가상 메모 노출 검사

학생은 다음 절차로 현재 배포와 GitHub 최신 코드에서 가상 메모가 노출되지 않았는지 확인합니다.

### 확인할 문장

프로젝트 `public/data.json`, `api/notes.js`, 배포 공개 함수 `/api/notes`에서 다음 네 문장을 찾습니다:
- `"메모 1: 방어전 출발 자료"`
- `"메모 2: 방어전 출발 자료"`
- `"메모 3: 방어전 출발 자료"`
- `"메모 4: 방어전 출발 자료"`

### GitHub 최신 파일 검색 (현재 main 브랜치)

1. 저장소 → **Code** 탭
2. 오른쪽 위 **Search this repository** (또는 `/` 단축키)
3. 검색어: `방어전 출발 자료`
4. 결과 기록:
   - 찾은 파일 경로와 줄 번호, 또는
   - 찾지 못함

### 배포된 `/data.json` 검색 (현재 Vercel 주소)

1. 배포 주소 + `/data.json` 방문 (예: `https://myapp.vercel.app/data.json`)
2. 브라우저 **페이지 소스 보기** (Ctrl+U / Cmd+U)
3. 페이지 내 검색 (Ctrl+F / Cmd+F): `방어전 출발 자료`
4. 결과 기록:
   - 찾은 횟수, 또는
   - 찾지 못함

### 배포된 `/api/notes` 검색 (현재 Vercel 주소)

1. 배포 주소 + `/api/notes` 방문 (예: `https://myapp.vercel.app/api/notes`)
2. 브라우저 **페이지 소스 보기**
3. 페이지 내 검색: `방어전 출발 자료`
4. 결과 기록:
   - 찾은 횟수, 또는
   - 찾지 못함

### 검사 시 주의

- **이번 점검은 현재 상태만 기록**: **지금 이 순간의 GitHub main 브랜치**와 **현재 배포된 Vercel 주소**에만 적용됩니다.
- **범위 밖: 옛 공개 커밋**: GitHub 커밋 내역(`/commits` 페이지)이나 저장소 이전 버전에서 가상 메모가 보이는 것은 이번 검사에 포함하지 않습니다. (향후 암호화나 히스토리 정책으로 해결)
- **범위 밖: 옛 배포**: Vercel의 이전 배포 URL, 웹 아카이브(Wayback Machine) 등 스냅샷 서비스에서 접근 가능한 과거 배포도 이번 검사 범위 밖입니다. (향후 배포 정책으로 해결)

### 검사 결과 예시 (1단계)

```
= 검사: 현재 상태 (GitHub main, 배포된 Vercel) =

✓ GitHub main 브랜치: 가상 메모 문장 없음
✓ Vercel /data.json: 가상 메모 문장 없음 (HTTP 404 또는 빈 배열)
✓ Vercel /api/notes: 가상 메모 문장 없음 (응답에 문장 없음)

⚠ 공개 API의 남은 약점:
   - 인증 없이 /api/notes 호출 가능
   - 인증 없이 /data.json 다운로드 가능

= 범위 밖 (이번 검사에서 확인하지 않음) =
✗ GitHub 이전 커밋 (commit history): 과거 버전에서 메모가 보일 수 있음
✗ Vercel 이전 배포 (이전 URL, 웹 아카이브): 과거 배포에서 메모가 보일 수 있음
```

---

## 2단계: 가상 메모를 Supabase API로 보호

2단계부터 화면은 `/api/notes` 서버 함수를 통해 Supabase에서 네 건의 가상 메모를 읽습니다. 서버 함수는 다음 환경변수를 읽습니다:

- `SUPABASE_URL`: Supabase 프로젝트 URL
- `SUPABASE_SECRET_KEY`: 서버 전용 API 키

### 가상 메모 노출 검사 (2단계)

1단계와 같은 절차로 검사합니다. 이번에는 `/data.json`이 **비어있거나 접근 불가**여야 하고, 메모는 **인증된 서버 API에서만** 읽혀야 합니다.

#### GitHub 최신 파일 검색 (현재 main 브랜치)

1. 저장소 → **Code** 탭
2. 오른쪽 위 **Search this repository** (또는 `/` 단축키)
3. 검색어: `방어전 출발 자료`
4. 결과 기록:
   - 찾은 파일 경로와 줄 번호, 또는
   - 찾지 못함

#### 배포된 `/data.json` 검색 (현재 Vercel 주소)

1. 배포 주소 + `/data.json` 방문 (예: `https://myapp.vercel.app/data.json`)
2. 브라우저 **페이지 소스 보기**
3. 페이지 내 검색: `방어전 출발 자료`
4. 결과 기록:
   - 찾은 횟수, 또는
   - 찾지 못함 (정상)

#### 배포된 `/api/notes` 검색 (현재 Vercel 주소)

1. 배포 주소 + `/api/notes` 방문 (예: `https://myapp.vercel.app/api/notes`)
2. 브라우저 **페이지 소스 보기**
3. 페이지 내 검색: `방어전 출발 자료`
4. 결과 기록:
   - 찾은 횟수, 또는
   - 찾지 못함 (정상)

#### 검사 결과 예시 (2단계)

```
= 검사: 현재 상태 (GitHub main, 배포된 Vercel) =

✓ GitHub main 브랜치: 가상 메모 문장 없음
✓ Vercel /data.json: 가상 메모 문장 없음 (빈 배열, HTTP 404, 또는 비보호)
✓ Vercel /api/notes: 가상 메모 문장 없음 (응답에 문장 없음)

⚠ 공개 API의 남은 약점 (2단계):
   - 인증 없이 /api/notes 호출 가능 (누구나 호출 가능)
   - 서버 키 노출 방지 (현재 키는 환경변수에서만 읽음, 응답에 포함 안 함)

= 범위 밖 (이번 검사에서 확인하지 않음) =
✗ GitHub 이전 커밋 (commit history): 과거 버전에서 메모가 보일 수 있음
✗ Vercel 이전 배포 (이전 URL, 웹 아카이브): 과거 배포에서 메모가 보일 수 있음
```

### 보안 약점 (2단계)

**현재 `/api/notes`는 다음 약점이 있습니다:**
- **인증 없음**: 로그인하지 않아도 누구나 호출 가능
- **접근 제어 없음**: 공개된 공개 함수(Public Serverless Function)
- **키 노출**: Supabase 서버 키를 사용하므로 응답에 키가 담기면 안 됨 (현재는 환경변수에서만 읽음)

**다음 단계에서 보호할 사항:**
- 로그인 사용자만 호출 가능하게 (3단계 이후)
- 사용자별 거절 규칙 추가
- 부정 행위 모니터링

환경변수는 Vercel 배포 설정의 **비밀 입력란**에만 넣고, 코드나 로그에 값을 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 만듭니다. 1단계에서는 `public/data.json`도 복사합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 학생의 실제 주소를 넣습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 반 엔진이나 운영 심판의 공격 점검 규칙입니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름을 빼야 합니다. 대신 `api/notes.js`를 통해 서버 함수에서 Supabase를 읽습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/build-defense.mjs`를 통해 검증 결과를 Zip으로 만듭니다.
