#!/usr/bin/python
import time
import threading
import concurrent.futures

start = time.perf_counter()

def pause():
    print("Sleeping for 10 seconds...")
    time.sleep(10)
    print("Done sleeping")

# thread1 = threading.Thread(target=pause)
# thread2 = threading.Thread(target=pause)

# thread1.start()
# thread2.start()

# print(threading.activeCount())
# print(threading.currentThread())
# print(threading.enumerate())

# thread1.join()
# thread2.join()

# finish = time.perf_counter()
# print(f"Isolated threading {(finish - start):.2f}")

with concurrent.futures.ThreadPoolExecutor() as executor:
    results = [executor.submit(pause) for _ in range(10)]
    for f in concurrent.futures.as_completed(results):
        print(f.result())

finish = time.perf_counter()
print(f"concurrent threading {(finish - start):.2f}")
