import time
import logging

logger = logging.getLogger('apate')


class test:
    def __init__(self):
        pass

    @staticmethod
    def time_count(base_fn):
        def time_test(*args, **kwargs):
            start_time = time.time()
            result = base_fn(*args, **kwargs)
            end_time = time.time()
            print(f"Task time : {end_time - start_time:.6f} seconds")
            return result

        return time_test


# Provide module-level time_count for backward compatibility
time_count = test.time_count


if __name__ == "__main__":
    import pytest
    import sys
    from pathlib import Path

    tests_dir = Path(__file__).parent
    sys.exit(pytest.main(["-v", str(tests_dir)]))
