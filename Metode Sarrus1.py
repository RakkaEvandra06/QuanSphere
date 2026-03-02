def determinant_sarrus(matrix):
    if len(matrix) == 3 and all(len(row) == 3 for row in matrix):
        # Matriks harus berukuran 3x3
        det = 0

        # Menggunakan metode Sarrus untuk menghitung determinan
        det += matrix[0][0] * matrix[1][1] * matrix[2][2]
        det += matrix[0][1] * matrix[1][2] * matrix[2][0]
        det += matrix[0][2] * matrix[1][0] * matrix[2][1]
        det -= matrix[2][0] * matrix[1][1] * matrix[0][2]
        det -= matrix[2][1] * matrix[1][2] * matrix[0][0]
        det -= matrix[2][2] * matrix[1][0] * matrix[0][1]

        return det
    else:
        print("Error: Matriks harus berukuran 3x3")

# Contoh penggunaan
matrix_3x3 = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
]

det_result = determinant_sarrus(matrix_3x3)

print(f"Determinan matriks:\n{matrix_3x3}\nadalah {det_result}")
