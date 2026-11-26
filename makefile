# Компилятор и флаги
CC = gcc
CFLAGS = -Wall -Wextra -O0 -g -Isrc/files.h 

# Пути
SRC_DIR = src/files.c
BUILD_DIR = build

# Исходники и объекты
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))

# Имя исполняемого файла
TARGET = ids

# Главная цель
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)
	@echo "✓ Сборка завершена: $(TARGET)"

# Компиляция .c → .o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Создание папки build
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Очистка
clean:
	rm -rf $(BUILD_DIR) $(TARGET)
	@echo "✓ Очистка завершена"

# Запуск
run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run