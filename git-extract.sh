#!/bin/bash

# Función de ayuda para mostrar uso
usage() {
    echo "Uso: $0 <URL_del_repositorio> <subdirectorio_a_extraer>"
    echo "Ejemplo: $0 https://github.com/user/infra.git services/backend/api"
    exit 1
}

# --- 1. Verificación de argumentos ---
if [ "$#" -ne 2 ]; then
    usage
fi

REPO_URL="$1"
SUBDIR="$2"
# Extraemos el nombre del repositorio (ej. 'infra')
REPO_NAME=$(basename "$REPO_URL" .git)
TEMP_DIR="${REPO_NAME}_temp_sparse_checkout"

echo "⚙️ Iniciando extracción dispersa para el subdirectorio: '$SUBDIR'"
echo "   Desde el repositorio: '$REPO_URL'"
echo "--------------------------------------------------------"

# --- 2. Clonación Inicial (sin archivos) ---
echo "1/4: Clonando el repositorio '$REPO_NAME' sin extraer archivos..."
if ! git clone --no-checkout "$REPO_URL" "$TEMP_DIR"; then
    echo "❌ Error al clonar el repositorio. Verifique la URL."
    exit 1
fi

cd "$TEMP_DIR"

# --- 3. Configuración de Sparse Checkout ---
echo "2/4: Configurando Git para 'Sparse Checkout' (Modo Cono)..."
git sparse-checkout init --cone

# El comando 'set' define qué carpetas incluir.
echo "3/4: Definiendo la ruta '$SUBDIR'..."
if ! git sparse-checkout set "$SUBDIR"; then
    echo "❌ Error al establecer la ruta de extracción dispersa."
    cd ..
    rm -rf "$TEMP_DIR"
    exit 1
fi

# --- 4. Extracción de los Archivos ---
# Extrae solo los archivos necesarios a la carpeta temporal
echo "4/4: Extrayendo archivos y haciendo checkout de la rama principal..."
if ! git checkout main; then
    # Intenta con 'master' si 'main' falla (para repositorios antiguos)
    if ! git checkout master; then
        echo "⚠️ Advertencia: No se pudo hacer checkout de 'main' o 'master'."
        echo "   Intentando checkout sin especificar rama (usará la rama por defecto)."
        git checkout
    fi
fi

# --- 5. Traslado y Limpieza ---
cd ..

# Asegurarse de que la carpeta de destino no exista antes de mover
TARGET_FOLDER=$(basename "$SUBDIR")
if [ -d "$TARGET_FOLDER" ]; then
    echo "❌ La carpeta de destino '$TARGET_FOLDER' ya existe en el directorio actual. Limpie o cambie el nombre."
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo "✅ Extracción completada. Moviendo el contenido de '$SUBDIR' a '$TARGET_FOLDER'..."

# Mover el contenido real (la carpeta deseada) al directorio actual
if [ -d "$TEMP_DIR/$SUBDIR" ]; then
    mv "$TEMP_DIR/$SUBDIR" "$TARGET_FOLDER"
    echo "✨ El contenido de '$SUBDIR' ahora está en la carpeta: './$TARGET_FOLDER'"
else
    echo "⚠️ Advertencia: El subdirectorio '$SUBDIR' no fue encontrado después de la extracción."
fi

# Limpieza: Elimina el directorio temporal
rm -rf "$TEMP_DIR"

echo "--------------------------------------------------------"
echo "🎉 ¡Script finalizado con éxito!"
