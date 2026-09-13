class test:
    def __init__(self):
        pass

    def time_count(base_fn):
        def time_test(*args, **kwargs):
            import time

            start_time = time.time()
            result = base_fn(*args, **kwargs)
            end_time = time.time()
            print(f"Task time : {end_time - start_time} seconds")

        return time_test()
