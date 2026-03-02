import numpy as np

# Coefficients matrix
coefficients_matrix = np.array([[1, 2, -1],
                                [1, -1, -1],
                                [1, 1, -3]])

# Constants matrix
constants_matrix = np.array([-1, 3, -2])

# Calculate the determinant of the coefficients matrix
det_coefficients = np.linalg.det(coefficients_matrix)

# Create a copy of the coefficients matrix to replace columns with constants
matrix_x = coefficients_matrix.copy()
matrix_y = coefficients_matrix.copy()
matrix_z = coefficients_matrix.copy()

# Replace columns with constants
matrix_x[:, 0] = constants_matrix
matrix_y[:, 1] = constants_matrix
matrix_z[:, 2] = constants_matrix

# Calculate the determinants for X, Y, and Z using numpy's linalg.det
det_x = np.linalg.det(matrix_x)
det_y = np.linalg.det(matrix_y)
det_z = np.linalg.det(matrix_z)

# Calculate the solutions using Cramer's Rule
x = det_x / det_coefficients
y = det_y / det_coefficients
z = det_z / det_coefficients

# Print the solutions
print("Jawaban:")
print(f"X = {x}")
print(f"Y = {y}")
print(f"Z = {z}")
