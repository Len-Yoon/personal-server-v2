"""로컬 테스트 → V2 ARM64 이미지 등록·검증 → 명세 갱신. 자동 배포하지 않음."""
import sys
import unittest
import build_data
import lab


def run_tests():
    # 현재 실행기의 의존성이 부족해 skip된 검증도 성공으로 처리하지 않음.
    suite = unittest.defaultTestLoader.discover(str(lab.ROOT / 'tests'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or result.testsRun == 0:
        raise RuntimeError('배포 준비 테스트 실패 또는 미실행 항목 존재')


def main():
    build_data.prepare(run_tests=run_tests)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # 드라이버·인증·registry 오류에 포함될 수 있는 외부 응답은 비출력함.
        print('V2 배포 준비 실패: 테스트 결과·도구·소유 경계·이미지 및 명세 일치를 확인해야 함', file=sys.stderr)
        raise SystemExit(1) from None
