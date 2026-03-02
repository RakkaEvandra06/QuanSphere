import time
from threading import Thread, Lock
import sys

lock = Lock()

def animate_text(text, delay=0.1):
    with lock:
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

def sing_lyric(lyric, delay, speed):
    time.sleep(delay)
    animate_text(lyric, speed)

def sing_song():
    lyrics = [
        ("Kan ku arungi tujuh laut samudra", 0.06),
        ("Kan ku daki pegunungan himalaya", 0.06),
        ("Apapun kan ku lakukan tuk dirimu sayang...", 0.06),
        ("Oh penjaga hatiku...", 0.07),
        ("Ohh ohh ohh", 0.15)
    ]
    
    """Delay Untuk Setiap Lirik Dalam Detik.
    Ini Adalah Waktu Tunggu Sebelum Lirik Dimulai."""
    delays = [0.5, 6.2, 12.2, 17.6, 24.6]
    
    threads = []
    for i in range(len(lyrics)):
        lyric, speed = lyrics[i]
        t = Thread(target=sing_lyric, args=(lyric, delays[i], speed))
        threads.append(t)
        t.start()
    
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    sing_song()