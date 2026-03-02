def hitung_determinan_sarrus(matriks):
    if len(matriks) != 3 or len(matriks[0]) != 3:
        raise ValueError("Metode Sarrus hanya berlaku untuk matriks 3x3.")

    det = 0

    # Menghitung determinan menggunakan metode Sarrus
    det += matriks[0][0] * matriks[1][1] * matriks[2][2]
    det += matriks[0][1] * matriks[1][2] * matriks[2][0]
    det += matriks[0][2] * matriks[1][0] * matriks[2][1]

    det -= matriks[0][2] * matriks[1][1] * matriks[2][0]
    det -= matriks[0][0] * matriks[1][2] * matriks[2][1]
    det -= matriks[0][1] * matriks[1][0] * matriks[2][2]

    return det

# Contoh penggunaan
matriks_sarrus = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
]

determinan = hitung_determinan_sarrus(matriks_sarrus)
print(f"Determinan matriks: {determinan}")
