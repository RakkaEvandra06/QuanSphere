# Fungsi untuk membuat matriks dengan baris dan kolom tertentu
def buat_matriks(baris, kolom):
    matriks = []
    for i in range(baris):
        # Menambahkan baris kosong ke dalam matriks
        matriks.append([])
        for j in range(kolom):
            # Menambahkan elemen ke dalam baris
            matriks[i].append(2)  # Anda dapat mengganti 0 dengan nilai yang diinginkan
    return matriks

# Fungsi untuk menampilkan matriks
def tampilkan_matriks(matriks):
    for baris in matriks:
        print(baris)

# Contoh penggunaan
baris = 3
kolom = 4
matriks_saya = buat_matriks(baris, kolom)
tampilkan_matriks(matriks_saya)
