# HTTP 중계 계층의 파서 불일치와 요청 경계 desync

HTTP/1.1 중계기와 백엔드가 같은 바이트열의 **요청 종료 지점**을 다르게 판단할 때 어떤 일이 생기는지 연구하는 로컬 실험실입니다. 결정적 파서 모델로 경계 불일치의 기제를 검증하고, 격리된 Docker 환경에서 Nginx 1.28.3 또는 HAProxy 3.2.23과 Apache httpd 2.4.68의 실제 전달 바이트·요청 로그·클라이언트 응답을 관측했습니다. `Content-Length`(CL), `Transfer-Encoding`(TE), 상충하는 중복 CL에 집중합니다. `example.invalid`과 합성 경로만 사용하며 외부 호스트로 실험 트래픽을 보내지 않습니다.

> **결론:** 아래에 명시한 제품 버전·설정·고정 입력에서는 요청 경계 desync나 후속 합성 요청의 백엔드 실행이 관측되지 않았습니다. 이는 다른 설정·버전·입력의 안전성을 보증하는 취약점 판정이 아닙니다.

## 증거 수준과 핵심 결과

- **실제품 관측:** Nginx→Apache, HAProxy→Apache를 각각 7개 고정 입력으로 두 번 실행했고, Apache 직접 기준선도 7개 입력으로 실행했습니다. 매 사례는 새 Compose 프로젝트에서 수행했습니다. 이미지 다이제스트, 설정 해시, 원본 입력·응답, 중계기→백엔드 바이트열, 연결 포트와 서비스 로그를 [실측 기록](results/real/)에 보존했습니다.
- **정상 대조군:** 단일 GET, 연속 GET, 정상 CL, 정상 chunked 모두 완전한 HTTP 200 응답과 예상 백엔드 요청 수를 보였습니다. 두 요청 사례에서 동일 백엔드 연결의 재사용도 로그로 확인했습니다. 정상 chunked 입력은 Nginx가 본문을 풀어 CL로 전달했고, HAProxy는 chunked 형식을 유지했습니다.
- **모호 입력:** Nginx는 CL+TE 두 사례와 상충 중복 CL을 400으로 거부하고, 관측된 백엔드 전달 바이트는 0이었습니다. HAProxy는 CL+TE 두 사례에서 CL을 제거한 단일 요청만 백엔드에 전달하고 클라이언트 연결을 닫았습니다. 상충 중복 CL은 HAProxy 로그에 400으로 남았고 백엔드 전달은 없었으나, 클라이언트는 응답 바이트 없이 EOF를 받았습니다. Apache 직접 기준선에서는 CL+TE 두 사례에 첫 POST 한 건의 200 응답 후 연결 종료, 상충 중복 CL에는 400과 연결 종료가 관측됐습니다.
- **모델에서 관측:** 정상 입력 2개는 경계가 일치했고, *의도적으로 상반된 비표준 정책*을 지정한 모호 입력 3개는 첫 경계가 달랐습니다. 이는 실제 제품의 취약성 증거가 아니라 기제 설명입니다.

실측에서 relay는 HTTP를 해석하지 않고 소켓 쓰기가 완료된 바이트를 기록합니다. 이는 패킷 캡처나 백엔드 커널 수신의 직접 증명이 아닙니다. 백엔드 접근 로그·연결 식별자와 함께 해석했습니다. 상세 방법과 원시 기록 읽는 법은 [실제품 실험 설명](real_lab/README.md)에 있습니다.

특히 모델의 `te-first` 정책은 TE와 CL이 함께 있는 요청 이후에도 후속 바이트를 파싱합니다. [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1)은 이런 요청을 처리한 서버에 응답 후 연결 종료를 요구하므로, 이 정책은 표준 적합 구현을 나타내지 않습니다.

## 실제품 Docker 실증

[Compose 구성](compose.yaml)은 **Nginx 1.28.3 → 바이트 중계 relay → Apache httpd 2.4.68**, [대체 구성](compose.haproxy.yaml)은 **HAProxy 3.2.23 → relay → Apache**입니다. [실행기](real_lab/run.py)는 사례마다 새 내부 Docker 네트워크를 만들고 종료 후 정리합니다. 호스트 공개 포트는 없으며 이미지 다이제스트는 Compose 파일과 각 실행의 `images.json`에 고정·기록했습니다. relay는 HTTP를 해석하거나 변경하지 않습니다. [분석기](real_lab/analyze.py)는 클라이언트·relay·프록시·Apache 기록을 결합해 관측 사실을 출력하며 취약점 판정을 자동화하지 않습니다.

같은 7개 입력을 Nginx와 HAProxy에서 각각 2회, Apache 직접 연결에서 1회 실행했습니다. CL.TE·TE.CL은 고정 입력의 이름이며 실제품 파서가 그 우선순위를 택했다는 뜻이 아닙니다. 35사례 모두 실행 명령이 성공했고, 20개 정상 대조군 검사도 통과했습니다. 사례별 입력 SHA-256은 5회 실행에서 일치했습니다. [보관 기록 검증기](real_lab/verify_archive.py)를 다시 실행한 결과도 `PASS (5/5 archives, 7 cases each)`였습니다. 첫 Nginx 실행의 manifest에는 edge/target 필드가 없고, 두 Nginx 실행의 클라이언트 코드 해시는 다릅니다. 다만 기록된 입력 바이트와 결과는 일치합니다. 주요 원시 기록은 [Nginx 1차](results/real/nginx1283-httpd2468-a1/manifest.json)·[2차](results/real/nginx1283-httpd2468-a2/manifest.json), [HAProxy 1차](results/real/haproxy3223-httpd2468-a1/manifest.json)·[2차](results/real/haproxy3223-httpd2468-a2/manifest.json), [Apache 직접](results/real/apache2468-direct-a1/manifest.json)에 있습니다. 각 `manifest.json`에는 구성 해시와 사례별 실행 결과가, 사례 폴더에는 원본 바이트와 로그가 있습니다.

| 입력 | Nginx → Apache | HAProxy → Apache | Apache 직접 |
| --- | --- | --- | --- |
| 단일 GET·연속 GET·정상 CL·정상 chunked | 예상 수의 완전한 200 응답과 Apache 요청; 2요청 사례에서 같은 백엔드 연결 재사용 | 동일 | 예상 수의 완전한 200 응답과 요청 |
| CL.TE | 클라이언트 400·EOF; relay 전달 0바이트, Apache 요청 0건 | CL 제거, 유효한 chunked 단일 POST 전달; 200·EOF; 후속 합성 요청 0건 | 단일 POST 200·EOF; 후속 합성 요청 0건 |
| TE.CL | 클라이언트 400·EOF; relay 전달 0바이트, Apache 요청 0건 | CL 제거, 유효한 chunked 단일 POST 전달; 200·EOF; 후속 합성 요청 0건 | 단일 POST 200·EOF; 후속 합성 요청 0건 |
| 상충 중복 CL | 클라이언트 400·EOF; relay 전달 0바이트, Apache 요청 0건 | 프록시 로그 400, 클라이언트 수신 **0바이트** 후 EOF; relay 전달 0바이트 | 클라이언트 400·EOF; Apache 접근 로그에 거부된 POST 1건(400) |

정상 chunked 입력은 Nginx가 청크를 풀어 `Content-Length: 4`로 전달했고, HAProxy는 chunked 프레이밍을 유지했습니다. 이는 원본 입력만 비교하면 실제 백엔드 수신 메시지를 잘못 추정할 수 있음을 보여 줍니다. 정상 사례의 클라이언트 `read_timeout`은 완전한 응답을 받은 뒤 지속 연결에서 추가 응답/EOF를 기다린 결과이며 정상 대조군 실패가 아닙니다. HAProxy 모호 입력에서 확인한 종료는 **클라이언트 측 EOF**입니다. relay의 `drained` 기록은 소켓 쓰기 완료 기록으로, 패킷 캡처는 아닙니다.

재현하려면 Docker 엔진·Compose와 Python 3.10 이상이 필요합니다. 먼저 `docker compose -f compose.yaml config --quiet`와 `docker compose -f compose.haproxy.yaml config --quiet`로 설정을 확인하고 Compose 파일의 다이제스트 이미지를 로컬에 준비합니다. 저장소 루트에서 고유한 run ID로 실행합니다.

```powershell
docker pull nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
docker pull haproxy:3.2.23-alpine@sha256:5961c68bc8a81c5124d0a98ab20f81b74717d6afe596e805977d9cf84c126222
docker pull httpd:2.4-alpine@sha256:4e585da9d0125dec36d4500a9f5c5df7b2c0a01f67cb47865a91a4b05bdbec1b
docker pull python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

python real_lab/run.py --edge nginx --case all --run-id nginx-repro
python real_lab/run.py --edge haproxy --case all --run-id haproxy-repro
python real_lab/run.py --target backend --case all --run-id apache-repro
python real_lab/analyze.py results/real/nginx-repro
python real_lab/analyze.py results/real/haproxy-repro
python real_lab/analyze.py results/real/apache-repro
python real_lab/verify_archive.py
```

실행기가 이미지를 자동으로 받지 않으므로 최초 1회는 `docker pull`로 [Compose 파일](compose.yaml)과 [HAProxy Compose 파일](compose.haproxy.yaml)의 이미지 참조를 내려받아야 합니다. 연구 절차와 로그 필드의 의미는 [실제품 실험 설명](real_lab/README.md)을 참조하세요.

## 결정적 모델: 연구 질문과 판정 범위

**질문.** 중계기가 백엔드와 다른 본문 길이 규칙을 적용한 채 원본 요청 바이트를 전달하면, 양쪽에서 본 요청의 개수와 경계가 달라지는가?

**판정 기준.** 동일한 입력과 동일한 연결을 가정하고, 양쪽이 첫 요청을 수락했으며 첫 요청의 종료 바이트 오프셋이 다를 때만 `confirmed_boundary_mismatch`로 판정합니다. 한쪽이 입력을 거부하거나 후속 요청에서 오류가 난 사실만으로는 실제 연결의 desync나 보안 영향을 확정하지 않습니다. 출력에는 각 파서의 요청 목록, 경계, 오류를 함께 남깁니다.

모델의 데이터 흐름은 다음과 같습니다. 중계기 역할 파서가 전체 입력에서 완성된 요청 구간만 추출해 원본 바이트 그대로 백엔드 역할 파서에 전달합니다. 부분 수신 중 먼저 전달되는 바이트는 모델링하지 않습니다.

```text
실험 입력 바이트 ──> 중계기 역할 파서 ──[원본 바이트 전달 가정]──> 백엔드 역할 파서
                         │                                      │
                         └──── 요청 종료 오프셋과 수락 결과 비교 ─┘
```

`cl-te`는 중계기가 CL을, 백엔드가 TE를 우선하는 조합입니다. `te-cl`은 반대입니다. 이름은 **중계기.백엔드** 순서이며, 실제 제품을 지칭하지 않습니다. 두 헤더를 함께 보낸 요청은 정상적인 클라이언트 요청이 아니며, [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)은 이런 입력을 오류로 취급할 것을 권고합니다. 중계기가 전달하기로 했다면 수신한 CL을 제거하고 TE를 처리한 뒤 전달해야 합니다.

## 모델 재현

Python 3.10 이상만 필요합니다. 다음 명령은 네트워크를 사용하지 않습니다.

```powershell
python desync_lab.py matrix --pretty
python -m unittest discover -s tests -v
```

첫 명령은 모든 고정 실험의 바이트열(`input_hex`), 두 파서의 요청 경계(`boundaries`), 거부 또는 불완전 메시지(`error`), 판정(`divergence`)을 JSON으로 출력합니다. 자동 처리에는 `--pretty`를 빼면 됩니다. 바이트 오프셋은 입력 시작을 0으로 두며, 각 경계는 **해당 요청 바로 뒤의 오프셋**입니다. 출력의 `schema_version`으로 형식을 식별할 수 있습니다.

모델의 최초 검증은 2026-09-20에 Windows, Python 3.14.7에서 수행했습니다. 아래 표는 저장소 테스트 및 위 명령으로 재검증할 수 있습니다. 모델은 Python 3.10+ 표준 라이브러리만 사용합니다.

## 실험 설계

| 실험 | 중계기 정책 | 백엔드 정책 | 통제/관찰 목적 |
| --- | --- | --- | --- |
| `cl-normal` | `strict` | `strict` | 모호하지 않은 CL 본문 뒤의 정상 요청을 양쪽이 동일하게 파싱하는지 확인 |
| `chunked-normal` | `strict` | `strict` | 정상 chunked 종결 뒤의 요청을 양쪽이 동일하게 파싱하는지 확인 |
| `cl-te` | `cl-first` | `te-first` | CL/TE 우선순위 차이에 따른 첫 요청 경계 비교 |
| `te-cl` | `te-first` | `cl-first` | 우선순위를 뒤집었을 때의 첫 요청 경계 비교 |
| `duplicate-cl` | `duplicate-cl-first` | `duplicate-cl-last` | 상충하는 중복 CL에서 첫 값/마지막 값 선택 차이 비교 |

`strict`는 연구용 방어 기준 정책으로 모호한 길이 정보를 거부합니다. 나머지는 실제 서버의 기본 설정을 주장하는 이름이 아니라, 위험한 과거/비표준 처리 방식을 분리해 관찰하기 위한 정책입니다. 모든 페이로드는 코드 안의 고정 바이트열입니다. HTTP 필드와 메시지 경계는 문자열 문자 수가 아니라 **옥텟**으로 처리해야 한다는 [RFC 9112 §2.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.2)를 따릅니다.

## 관측 결과

두 정상 대조군에서는 경계가 일치했습니다. 세 모호 입력에서는 두 파서가 모두 첫 요청을 완성했으나 종료 오프셋이 달랐습니다. 각 숫자는 입력 시작을 0으로 본 **배타적 종료 바이트 오프셋**입니다. 전체 원본 바이트와 두 파서의 결과는 [실험 기록](results/matrix.json)에 저장했습니다.

| 실험 | 중계기 경계 | 백엔드 경계 | 판정 및 후속 상태 |
| --- | --- | --- | --- |
| `cl-normal` | `[74, 122]` | `[74, 122]` | 일치, 양쪽 2요청 |
| `chunked-normal` | `[93, 141]` | `[93, 141]` | 일치, 양쪽 2요청 |
| `cl-te` | `[161, 209]` | `[104, 161, 209]` | 첫 경계 불일치. 백엔드가 `/synthetic-shadow`를 별도 요청으로 해석 |
| `te-cl` | `[166, 214]` | `[102, 159]` | 첫 경계 불일치. 백엔드는 `/synthetic-shadow`를 읽은 뒤 바이트 159에서 다음 요청 줄 오류 |
| `duplicate-cl` | `[95, 152, 200]` | `[152, 200]` | 첫 경계 불일치. 중계기만 `/synthetic-shadow`를 별도 요청으로 해석 |

모델 테스트 13개가 통과했습니다. 실제 실험 대조군 검사 테스트 4개를 포함한 전체 단위 테스트는 17개입니다. 테스트에는 첫 경계와 후속 요청의 실제 파싱, 모호 입력의 `strict` 거부, 동일한 두 CL의 정상 처리, 잘린 본문·청크의 미완료 판정, 중계기 오류 뒤 전달 중단, JSON CLI 형식과 모호 입력 3종의 동일 정책 짝 대조군이 포함됩니다. `te-cl`의 후속 요청 줄 오류는 **첫 경계 불일치와 별개의 결과**입니다. 실제 연결 재사용이나 응답 오염이 확인됐다는 뜻은 아닙니다.

## 결과 읽는 법

| 결과 | 의미 |
| --- | --- |
| 양쪽 첫 경계 동일, 오류 없음 | 이 입력과 정책 조합에서 경계 desync가 관찰되지 않음 |
| 첫 경계가 다르고 양쪽이 수락 | 모델에서 요청 경계 불일치 확인 |
| 한쪽이 거부 | 파싱 정책 차이. 이 사실만으로 후속 요청 desync를 확정할 수 없음 |
| 후속 요청 파싱 오류 | 첫 경계 이후의 스트림 해석에 문제가 있음. 최초 불일치와 별도로 기록 |

핵심 증거는 HTTP 응답 코드가 아니라 **동일 바이트 오프셋에 대한 서로 다른 요청 구획**입니다. 실제 서비스에서는 공유 백엔드 연결과 응답 순서가 맞물려 영향이 커질 수 있지만, 결정적 모델은 요청 파싱 경계까지만 판정합니다. 연구 코드가 임의의 외부 주소를 대상으로 탐침을 보내거나 서비스의 취약성을 자동 판정하지 않습니다.

## 표준과 방어 해석

- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): 서버는 TE와 CL이 함께 있는 요청을 거부하거나 TE로 처리할 수 있지만, 응답 후 연결을 닫아야 합니다.
- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): TE가 CL에 우선합니다. 중계기가 해당 요청을 전달한다면 CL을 제거하고 TE를 처리한 뒤 전달해야 합니다. 잘못된 CL은 동일한 유효 십진값으로 이루어진 쉼표 목록의 허용 가능한 정규화 예외를 제외하면 복구 불능 길이 오류입니다.
- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): CL은 음수가 아닌 십진 옥텟 수입니다. 잘못되거나 실제 메시지 길이와 맞지 않는 CL을 전달해서는 안 됩니다.
- [RFC 9112 §5.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.1): 필드명과 콜론 사이 공백이 있는 요청은 400으로 거부해야 합니다. 이 사례는 향후 헤더 가시성 차이 연구에서 중요합니다.
- [RFC 9112 §9.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-9.3): 지속 연결에서 서버는 요청 본문을 모두 읽거나 연결을 닫아, 남은 바이트가 다음 요청으로 해석되는 일을 막아야 합니다.
- [RFC 9112 §11.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-11.2): 요청 스머글링은 수신자 간 프로토콜 파싱 차이로 추가 요청을 숨기는 문제입니다.

운영 환경에서는 중계기와 백엔드의 파싱 규칙을 일치시키고, 모호한 길이·문법 입력을 거부하며 연결을 닫는 것이 우선입니다. 중계 후 전달하는 메시지는 홉마다 길이 정보를 새로 계산해 일관되게 만들고, 백엔드 연결 재사용 정책을 포함해 검증해야 합니다. 본 모델의 `strict` 선택은 이런 원칙을 보여 주는 **좁은 방어 예시**이지 HTTP/1.1 전체 적합성 인증이 아닙니다.

## 범위와 한계

이 연구는 HTTP/1.1 **요청**의 CL, 최종 `chunked` TE, 상충하는 중복 CL에 집중합니다. 결정적 모델은 헤더 16,384바이트·본문 1,048,576바이트 제한을 둡니다. 이는 연구 코드의 제한이며 RFC의 길이 제한이 아닙니다. 모델은 완성된 요청의 원본 바이트 전달을 가정하므로 실제 제품의 헤더 재작성·부분 수신·연결 종료 동작을 예측하지 않습니다.

실제품 결과는 **Nginx 1.28.3, HAProxy 3.2.23, Apache 2.4.68의 이 저장소 설정과 7개 고정 입력**에 한정됩니다. 사례당 클라이언트 TCP 연결 하나를 사용했습니다. 정상 사례에서 동일 백엔드 연결의 요청 재사용을 확인했지만, 다른 클라이언트가 공유 백엔드 연결에 들어오는 상황이나 교차 사용자 응답 오염을 시험하지 않았습니다. 캐시·인증, HTTP/2→HTTP/1.1 변환, 다른 길이 문법/인코딩, TCP 분할·시간차 변형, 다른 제품 버전·설정도 범위 밖입니다. 관측된 거부·정규화·연결 종료는 이 범위 안에서만 해석할 수 있습니다.

후속 연구에서는 소유·허가된 격리 환경에서 요청·응답 대응과 공유 백엔드 연결을 추가로 검증할 수 있습니다. 헤더 공백, 접힘, LF 단독 줄끝은 구현마다 허용 가능한 처리도 다르므로 단순 거부 여부만으로 결함을 판정해서는 안 됩니다. 예를 들어 [RFC 9112 §5.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.2)는 요청의 구식 줄 접힘을 거부하거나 공백으로 정규화하는 처리를 허용합니다.

## 참고 문헌

1. IETF, [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112.html), 2022.
2. IETF, [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html), 2022.
3. Linhart 외, [HTTP Request Smuggling](https://www.cgisecurity.com/lib/HTTP-Request-Smuggling.pdf), 2005. RFC 9112가 인용한 초기 연구.
4. James Kettle, [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn), 2019. CL.TE/TE.CL 분류와 두 홉 실험의 맥락.
5. James Kettle, [HTTP/1.1 Must Die](https://portswigger.net/research/http1-must-die), 2025. CL/TE 외 파서 불일치로 연구 범위를 확장한 후속 연구.
