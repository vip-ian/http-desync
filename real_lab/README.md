# 실제 HTTP 두 홉 관측 환경

Nginx 1.28.3 또는 HAProxy 3.2.23을 프록시로, Apache httpd 2.4.68을 백엔드로 실행합니다. 공식 이미지가 다이제스트로 고정되어 있습니다. Compose `internal` 네트워크만 쓰며 호스트 공개 포트는 없습니다. 모든 경로·호스트명은 합성 값입니다.

`relay.py`는 HTTP를 파싱하거나 수정하지 않고 프록시와 Apache 사이의 바이트를 전달합니다. 연결별 양방향 `drained` 이벤트의 hex·길이·SHA-256과 백엔드 소켓 포트를 `relay.jsonl`에 기록합니다. 이 이벤트는 소켓 쓰기 완료 관측이며 패킷 캡처는 아닙니다. Apache의 `LAB_BACKEND` 로그는 요청·상태·연결 포트·지속 연결 요청 번호를 기록합니다.

## 준비와 실행

저장소 루트에서 Docker 엔진과 Python 3.10 이상을 사용합니다. 두 Compose 설정을 확인하고, [Nginx 구성](../compose.yaml) 및 [HAProxy 구성](../compose.haproxy.yaml)에 적힌 이미지 참조를 `docker pull`로 내려받습니다. 실행기는 `--pull never`로 고정 이미지만 사용합니다.

```powershell
docker compose -f compose.yaml config --quiet
docker compose -f compose.haproxy.yaml config --quiet
python real_lab/run.py --edge nginx --case all --run-id nginx-repro
python real_lab/run.py --edge haproxy --case all --run-id haproxy-repro
python real_lab/run.py --target backend --case all --run-id apache-repro
python real_lab/analyze.py results/real/nginx-repro
python real_lab/analyze.py results/real/haproxy-repro
python real_lab/analyze.py results/real/apache-repro
python real_lab/verify_archive.py
```

`--run-id`는 매 실행마다 새 값이어야 합니다. 생략하면 실행기가 생성합니다. `--case`로 7개 중 한 사례만 선택할 수도 있습니다. `--target backend`는 프록시를 거치지 않는 Apache 직접 기준선입니다. 실행기는 각 사례에 새 Compose 프로젝트를 만들고, 종료 시 그 프로젝트의 컨테이너를 정리합니다.

`--case all`은 단일 GET, 연속 GET, 정상 CL, 정상 chunked 대조군을 먼저 실행합니다. 완전한 200 응답의 수, 클라이언트 송신 완료, relay 전달(프록시 경유일 때), Apache `LAB_BACKEND` 요청 수와 종류가 기대값과 다르면 모호 입력 실행을 중단합니다. 이후 CL.TE, TE.CL, 상충 중복 CL을 각각 실행합니다. 단위 검사에는 `python -m unittest discover -s tests -v`를 사용합니다.

## 결과 파일과 해석

`results/real/<run-id>/manifest.json`은 이미지·구성·명령 기록과 각 사례의 종료 코드를 연결합니다. `images.json`에는 실제 이미지 ID와 다이제스트가 있습니다. 각 사례 폴더의 `client.json`은 원본 입력·응답 hex와 EOF/시간 초과를, `relay.jsonl`은 양방향 전달 바이트를, `edge.log`와 `backend.log`는 제품 로그를 보존합니다. `relay.jsonl`의 `backend_local` 포트는 Apache의 `port=%{remote}p`에 대응합니다. 한 연결의 `edge_to_backend` 이벤트를 `sequence` 순으로 합치면 백엔드 방향으로 기록된 스트림을 재구성할 수 있습니다.

[보관 기록 검증기](verify_archive.py)는 저장된 최종 5회 실행의 35사례를 읽기 전용으로 대조합니다. 명령 성공, 대조군, 입력 해시, 프록시 전달 바이트·백엔드 요청, 반복 실행의 관측값을 검사합니다. 검증은 기록의 일관성을 확인하며 파일 서명이나 취약점 판정은 아닙니다. [분석기](analyze.py)는 기록을 읽기만 하고 취약점 여부를 자동 판정하지 않습니다. 상태 코드나 시간 초과 하나만으로 요청 경계 desync를 판정하지 마세요. 정상 사례의 `read_timeout`은 완전한 응답 뒤 지속 연결에서 기다린 결과입니다. HAProxy 상충 중복 CL 사례는 **프록시 로그에 400이 있지만 클라이언트 응답 바이트는 0개**입니다. HAProxy CL+TE 사례에서는 클라이언트 쪽 EOF가 관측됐으며, 이 사실만으로 Apache가 연결을 닫았다고 단정할 수 없습니다. relay의 `ConnectionResetError` 기록도 연결 정리 중 발생한 소켓 오류 관측으로, 그 자체가 요청 경계 불일치 증거는 아닙니다.

Nginx의 헤더·본문 재작성은 원본 입력과 전달 바이트를 다르게 만듭니다. 실제 전달 스트림과 Apache 요청 로그를 함께 비교해야 합니다. 정상 요청의 백엔드 연결 재사용은 relay 연결 ID와 Apache `port`·`keepalive`로 확인했습니다. 사례당 클라이언트 연결 하나를 사용했고 캐시·인증·HTTP/2 변환·교차 클라이언트 공유 연결은 시험하지 않았습니다.

설정은 [Nginx upstream 공식 문서](https://nginx.org/en/docs/http/ngx_http_upstream_module.html), [HAProxy 공식 구성 문서](https://docs.haproxy.org/3.2/configuration.html), [Apache 공식 로그 문서](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html)를 참고했습니다.
