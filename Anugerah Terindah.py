import time
import sys

def print_karaoke_lyrics(lyrics, delay_per_char=0.1, delay_per_line=1.0):
    """
    Menampilkan lirik lagu dengan efek karaoke (huruf muncul satu per satu).
    
    Parameters:
        lyrics (list): Daftar string berisi lirik lagu per baris
        delay_per_char (float): Delay antara munculnya setiap karakter (detik)
        delay_per_line (float): Delay antara munculnya setiap baris (detik)
    """
    for line in lyrics:
        # Cetak setiap karakter satu per satu
        for char in line:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay_per_char)
        
        # Delay setelah baris selesai
        time.sleep(delay_per_line)
        print()  # Pindah ke baris baru

# Contoh lirik lagu (bisa diganti dengan lirik apa saja)
lyrics = [
    "Ku Ingin kau jadi milikku...",
    "Temani diriku...",
    "Seumur hidupku dan ku...",
    "Berjanji tak akan sakiti...",
    "kau yang ku cinta sepenuh hati...",
    "Biarkan semua manusia...",
    "Jadi saksi nyata...",
    "Bahwa memilikimu adalah...",
    "Anugerah terindah...",
]

# Menjalankan fungsi karaoke
print_karaoke_lyrics(lyrics, delay_per_char=0.05, delay_per_line=1.5)