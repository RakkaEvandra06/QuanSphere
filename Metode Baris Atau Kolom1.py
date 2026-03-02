# Fungsi untuk membuat matriks dengan ukuran baris dan kolom tertentu
def buat_matriks(bar, kol):
    matriks = []
    for i in range(bar):
        # Tambahkan baris kosong sepanjang kolom
        matriks.append([0] * kol)
    return matriks

# Fungsi untuk menampilkan matriks
def tampilkan_matriks(matriks):
    for baris in matriks:
        print(baris)

# Contoh penggunaan
baris = 2
kolom = 3

matriks_saya = buat_matriks(baris, kolom)

# Isi matriks dengan nilai acak sebagai contoh
for i in range(baris):
    for j in range(kolom):
        matriks_saya[i][j] = i + j

tampilkan_matriks(matriks_saya)
