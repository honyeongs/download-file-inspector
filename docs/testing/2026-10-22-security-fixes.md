# 로컬 공개 테스트 기록

- 저장소: `download-file-inspector`
- 실행 시각(UTC): `2026-10-22T00:18:30.220091+00:00`
- 환경: Windows / Python 3.14.7
- 검사 당시 기준 커밋: `a4c00857234ab2ecebf025767cb8ab64e46e20cb`
- 보고서는 아직 커밋되지 않은 테스트 실행기 변경을 포함한 작업 트리를 검사한 결과입니다.
- 검사 대상 파일 48개의 정규화 SHA-256: `83588fc410f4323e7392598cab84782549ee1a8f8e8627b28053ad0b460abc67`
- 위 값은 소스 지문이며 개인 파일 해시나 디지털 서명이 아닙니다.

## 대표 시나리오 10개

기존 테스트 중 서로 다른 기능 10개를 선정하여 별도 재실행했습니다. 전체 회귀 검사와 중복되므로 독립 표본 20개로 합산하지 않습니다.

- **P01: Real project README copy and controlled byte mutation**
  결과: `passed`, 77.407 ms. 재현 대상: `tests.test_portfolio_files.ProjectFileTests.test_actual_readme_copy_and_mutation`.
- **P02: ZIP containing actual project source files**
  결과: `passed`, 65.594 ms. 재현 대상: `tests.test_portfolio_files.ProjectFileTests.test_zip_of_actual_project_sources`.
- **P03: ZIP parent and absolute path escape indicators**
  결과: `passed`, 0.791 ms. 재현 대상: `tests.test_zip_risks.ZipRiskTests.test_paths`.
- **P04: ZIP encrypted metadata indicator**
  결과: `passed`, 0.083 ms. 재현 대상: `tests.test_zip_risks.ZipRiskTests.test_encryption`.
- **P05: Bounded high compression ratio indicator**
  결과: `passed`, 2.417 ms. 재현 대상: `tests.test_zip_risks.ZipRiskTests.test_ratio`.
- **P06: Local/central ZIP header disagreement**
  결과: `passed`, 0.087 ms. 재현 대상: `tests.test_zip_risks.ZipRiskTests.test_header_disagreement`.
- **P07: No decompression or extraction during inspection**
  결과: `passed`, 89.62 ms. 재현 대상: `tests.test_zip_risks.ZipRiskTests.test_no_decompression_or_extraction`.
- **P08: Payload mutation does not imply a CRC check**
  결과: `passed`, 0.113 ms. 재현 대상: `tests.test_zip_risks.ZipRiskTests.test_crc_not_claimed`.
- **P09: Missing trusted reference is not integrity proof**
  결과: `passed`, 0.029 ms. 재현 대상: `tests.test_inspection.InspectionTests.test_missing_hash`.
- **P10: Bidirectional filename control indicator**
  결과: `passed`, 0.034 ms. 재현 대상: `tests.test_inspection.InspectionTests.test_bidi_filename`.

## 전체 자동 테스트

실행 76개: 통과 75, 실패 0, 오류 0, 건너뜀 1, fixture 오류 0.
전체 테스트별 결과와 소요 시간은 같은 폴더의 JSON에 기록했습니다.
- 건너뜀 사유 코드 `symlink_privilege`: 1개.

## 웹 검증

이번 실행에는 웹 검증을 포함하지 않았습니다.

## 공개 정보 범위

개인 폴더를 임의로 탐색하지 않았습니다. 테스트 코드가 지정한 프로젝트 파일과 격리된 임시 테스트 자료만 사용했습니다.
로그·계정·호스트·IP·명령줄·DB·세션/소스 토큰·예외 상세·절대 경로·브라우저 화면은 공개 보고서에서 제외했습니다.
기존 샘플의 이름은 가상 식별자이며 실제 개인정보를 단순 가명 처리한 자료가 아닙니다.
임시 DB 비밀번호·암호화 키·인증 토큰은 테스트 실행 중 생성되거나 코드의 명시적 테스트용 값이며 보고서로 내보내지 않습니다.

## 한계

- Two portfolio cases use actual tracked project files read locally; other cases use inert generated fixtures.
- Locally calculated reference hashes test comparison mechanics, not publisher authenticity.
- No malware execution, antivirus verdict, extraction, content CRC verification or download interception is performed.
- Windows symbolic-link cases may be skipped when the account lacks the required privilege.
- 성공은 해당 테스트의 기대 동작 일치이며 안전 인증·무결점·법적 적합성 보증이 아닙니다.
- 소요 시간은 이 PC의 단일 실행 관측값이며 성능 벤치마크가 아닙니다.
- 이 문서의 로컬 결과와 GitHub Actions의 원격 결과는 별개입니다.

## 재현

```console
python tools/run_portfolio_validation.py --suite all --browser --output reports/local-validation.json
```

Python 및 선택 의존성과 Playwright/Chromium 설치 방법은 README를 참고하세요.
대표 10개만 실행: `python tools/run_portfolio_validation.py --suite portfolio`.
개별 시나리오는 위 테스트 ID를 `python -m unittest <test_id> -v`로 실행할 수 있습니다.
PostgreSQL은 기본적으로 실행하지 않습니다. 운영 DB가 아닌 별도 테스트 DB에만 명시적으로 허용하세요.
