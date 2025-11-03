# antivirusTest

## 실행 환경 준비

1. Python 3.11 이상이 설치되어 있는지 확인합니다.
2. (선택) 가상 환경을 생성하고 활성화합니다.
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
3. 현재 레포는 표준 라이브러리만 사용하므로 추가 패키지 설치는 필요하지 않습니다.

## APK 스캐닝 실행 방법

`core.io.scan_apk` / `scan_dir` 함수를 이용해 APK 메타데이터를 추출할 수 있습니다. 아래 예시는 단일 파일과 디렉터리 스캔을 모두 수행합니다.

```bash
python - <<'PY'
from pathlib import Path
from core.io import scan_apk, scan_dir

# 단일 APK 스캔
apk_path = Path("/path/to/app.apk")
single_result = scan_apk(apk_path)
print("단일 APK 스캔 결과:", single_result)

# 디렉터리 전체 스캔 (중복 APK는 해시 캐시에 의해 건너뜀)
apk_dir = Path("/path/to/apk_dir")
dir_results = scan_dir(apk_dir, workers=4)
for result in dir_results:
    status = "OK" if result.ok else "ERROR"
    print(f"[{status}] {result.path} -> package={result.package_name}, sha256={result.sha256}")
PY
```

실패한 항목은 `result.errors`에 표준화된 코드(`ScanErrorCode`)와 함께 담기며, `cache_hit=True` 인 결과는 해시 캐시에 의해 스킵된 중복 APK를 의미합니다.

## 정적 피처 추출 실행 방법

APK 스캔 결과(`ApkScanResult`)를 `core.features_static.extract_static_features`에 전달하면 매니페스트/문자열/바이트코드 기반 피처를 수집할 수 있습니다.

```bash
python - <<'PY'
from pathlib import Path
from core.io import scan_apk
from core.features_static import extract_static_features

result = scan_apk(Path("/path/to/app.apk"))
features = extract_static_features(result, opcode_ngram=2)

print("권한 목록:", features.manifest.permissions)
print("추출된 URL 수:", len(features.urls))
print("Opcode n-gram 샘플:", list(features.opcode_profile.ngrams.items())[:5])
print("호출 그래프 통계:", features.call_graph)
PY
```

`features.missing_policy` 값으로 누락 데이터 처리 정책을 확인할 수 있으며, 파싱 실패가 발생한 경우 `MissingValuePolicy.NONE` 으로 설정됩니다.

## 코드 정적 점검

다음 명령으로 기본 정적 점검을 수행할 수 있습니다.

```bash
python -m compileall core
```
