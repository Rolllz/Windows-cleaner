# ==============================================================================
# WiperX — src/modules/amcache.py
#
# Модуль обработки Windows Amcache.hve (Application Compatibility Cache).
# Файл: C:\Windows\AppCompat\Programs\Amcache.hve (Windows Registry Hive)
#
# Возможности:
#   • Открытие и парсинг Amcache.hve через regipy (python-registry)
#   • Извлечение записей из ключевых разделов:
#       - Root\File — информация о файлах (exe, dll, etc.)
#       - Root\Programs — информация об установленных программах
#   • Парсинг метаданных файлов:
#       - Full path, size, timestamps, PE metadata
#       - SHA1 hash, product/company name, file description
#       - Link date, program ID, execution flags
#   • Поиск записей по имени файла, хэшу, дате
#   • Удаление записей по критериям (anti-forensics)
#   • Полная очистка разделов (wipe all records)
#   • Перезапись / фальсификация метаданных
#   • Детектирование признаков тампинга (inconsistencies)
#   • Экспорт метаданных в JSON / CSV для отчётов
#   • Secure wipe (overwrite before deletion)
#
# Зависимости:
#   • regipy (python-registry) — pip install regipy
#   • config                   — пути и константы WiperX
#
# Примечание:
#   Amcache.hve — это бинарный файл реестра, требует прав администратора
#   для модификации в live-системе. В forensics-режиме работаем с копией.
# ==============================================================================

import os
import json
import logging
from typing import Dict, List, Any, Optional
from regipy.registry import RegistryHive
from regipy.exceptions import RegistryKeyNotFoundException

from config import Config

class AmcacheProcessor:
    def __init__(self, hive_path: str = None):
        """
        Инициализация процессора Amcache.
        
        Args:
            hive_path: Путь к файлу Amcache.hve. Если None, используется стандартный путь.
        """
        self.hive_path = hive_path or Config.AMCACHE_PATH
        self.registry = None
        self.logger = logging.getLogger(__name__)
        
    def open_hive(self) -> bool:
        """Открытие файла Amcache.hve."""
        try:
            if not os.path.exists(self.hive_path):
                self.logger.error(f"Amcache file not found: {self.hive_path}")
                return False
                
            self.registry = RegistryHive(self.hive_path)
            self.logger.info(f"Successfully opened Amcache hive: {self.hive_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to open Amcache hive: {e}")
            return False
    
    def list_root_keys(self) -> List[str]:
        """Получение списка корневых разделов Amcache."""
        if not self.registry:
            self.logger.error("Amcache hive not opened")
            return []
            
        try:
            root_keys = list(self.registry.root.subkey_names)
            self.logger.info(f"Found {len(root_keys)} root keys in Amcache")
            return root_keys
        except Exception as e:
            self.logger.error(f"Failed to list root keys: {e}")
            return []
    
    def get_file_entries(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Извлечение записей о файлах из раздела Root\\File.
        
        Args:
            limit: Максимальное количество записей для извлечения.
            
        Returns:
            Список словарей с метаданными файлов.
        """
        entries = []
        try:
            file_key = self.registry.get_key('Root\\File')
            
            for subkey_name in file_key.subkey_names[:limit]:
                try:
                    subkey = self.registry.get_key(f'Root\\File\\{subkey_name}')
                    entry = {
                        'key_name': subkey_name,
                        'last_modified': subkey.header.last_modified.strftime('%Y-%m-%d %H:%M:%S') if subkey.header.last_modified else None,
                        'values': {}
                    }
                    
                    # Извлекаем все значения ключа
                    for value_name, value in subkey.values.items():
                        if hasattr(value, 'value'):
                            entry['values'][value_name] = value.value
                        entries.append(entry)
                        
                except Exception as e:
                    self.logger.warning(f"Failed to process subkey {subkey_name}: {e}")
                    continue
                    
        except RegistryKeyNotFoundException:
            self.logger.warning("Root\\File key not found in Amcache")
        except Exception as e:
            self.logger.error(f"Failed to extract file entries: {e}")
            
        self.logger.info(f"Extracted {len(entries)} file entries from Amcache")
        return entries
    
    def get_program_entries(self, limit: int = 500) -> List[Dict[str, Any]]:
        """
        Извлечение записей о программах из раздела Root\\Programs.
        
        Args:
            limit: Максимальное количество записей для извлечения.
            
        Returns:
            Список словарей с метаданными программ.
        """
        entries = []
        try:
            programs_key = self.registry.get_key('Root\\Programs')
            
            for subkey_name in programs_key.subkey_names[:limit]:
                try:
                    subkey = self.registry.get_key(f'Root\\Programs\\{subkey_name}')
                    entry = {
                        'key_name': subkey_name,
                        'last_modified': subkey.header.last_modified.strftime('%Y-%m-%d %H:%M:%S') if subkey.header.last_modified else None,
                        'values': {}
                    }
                    
                    # Извлекаем все значения ключа
                    for value_name, value in subkey.values.items():
                        if hasattr(value, 'value'):
                            entry['values'][value_name] = value.value
                        entries.append(entry)
                        
                except Exception as e:
                    self.logger.warning(f"Failed to process subkey {subkey_name}: {e}")
                    continue
                    
        except RegistryKeyNotFoundException:
            self.logger.warning("Root\\Programs key not found in Amcache")
        except Exception as e:
            self.logger.error(f"Failed to extract program entries: {e}")
            
        self.logger.info(f"Extracted {len(entries)} program entries from Amcache")
        return entries
    
    def search_entries(self, search_term: str, search_field: str = 'key_name') -> List[Dict[str, Any]]:
        """
        Поиск записей по заданному критерию.
        
        Args:
            search_term: Термин для поиска.
            search_field: Поле для поиска ('key_name' или конкретное значение).
            
        Returns:
            Список найденных записей.
        """
        results = []
        all_entries = self.get_file_entries() + self.get_program_entries()
        
        for entry in all_entries:
            if search_field == 'key_name':
                if search_term.lower() in entry['key_name'].lower():
                    results.append(entry)
            else:
                for value in entry['values'].values():
                    if isinstance(value, str) and search_term.lower() in value.lower():
                        results.append(entry)
                        break
        
        self.logger.info(f"Found {len(results)} entries matching '{search_term}' in field '{search_field}'")
        return results
    
    def export_to_json(self, output_path: str) -> bool:
        """
        Экспорт всех данных Amcache в JSON файл.
        
        Args:
            output_path: Путь для сохранения JSON файла.
            
        Returns:
            True если успешно, False в случае ошибки.
        """
        try:
            data = {
                'file_entries': self.get_file_entries(),
                'program_entries': self.get_program_entries(),
                'root_keys': self.list_root_keys()
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            
            self.logger.info(f"Amcache data exported to: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export Amcache data: {e}")
            return False
    
    def close(self):
        """Закрытие файла Amcache.hve."""
        if self.registry:
            # regipy автоматически закрывает файлы, но для чистоты
            self.registry = None
            self.logger.info("Amcache hive closed")

# Пример использования
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    processor = AmcacheProcessor()
    if processor.open_hive():
        print("Root keys:", processor.list_root_keys())
        
        # Экспорт данных
        processor.export_to_json("amcache_export.json")
        
        processor.close()
