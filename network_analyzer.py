import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import time
import psutil
import socket
import subprocess
import os
import sys
from collections import defaultdict, deque
from datetime import datetime
import json

# ⚡ Включите сюда исправленный FirewallManager из предыдущего артефакта
class FirewallManager:
    """Класс для управления Windows Firewall - ИСПРАВЛЕННАЯ ВЕРСИЯ"""
    
    def __init__(self):
        self.blocked_apps = set()
        self.rule_prefix = "NetworkAnalyzer_Block_"
        self.language_detected = None
        self.working_rules_command = None
        print(f"🔥 ИСПРАВЛЕННЫЙ FirewallManager - префикс: '{self.rule_prefix}'")
        
        self.detect_system_language()
        self.test_firewall_access()
        
    def detect_system_language(self):
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                  capture_output=True, text=True, timeout=10,
                                  encoding='utf-8', errors='ignore')
            
            if result.returncode == 0:
                output = result.stdout.lower()
                if any(word in output for word in ['параметры', 'профиль', 'состояние']):
                    self.language_detected = 'ru'
                elif any(word in output for word in ['settings', 'profile', 'state']):
                    self.language_detected = 'en'
                else:
                    self.language_detected = 'unknown'
            else:
                self.language_detected = 'unknown'
                
        except Exception as e:
            print(f"Ошибка определения языка: {e}")
            self.language_detected = 'unknown'
        
        return self.language_detected
    
    def is_admin(self):
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def test_firewall_access(self):
        print("\n🔥 === ИСПРАВЛЕННАЯ ДИАГНОСТИКА === 🔥")
        
        commands_to_test = [
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'dir=out'],
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'direction=outbound'],
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'],
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule'],
            ['netsh', 'firewall', 'show', 'config'],
        ]
        
        working_command = None
        best_score = 0
        
        for i, cmd in enumerate(commands_to_test):
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                      encoding='utf-8', errors='ignore')
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    rule_count = 0
                    
                    rule_indicators = [
                        'Rule Name:', 'Имя правила:', 'Nome da Regra:', 'Nom de la règle:'
                    ]
                    
                    for line in lines[:30]:
                        for indicator in rule_indicators:
                            if indicator in line:
                                rule_count += 1
                                break
                    
                    if rule_count > best_score:
                        best_score = rule_count
                        working_command = cmd
                        
            except Exception:
                continue
        
        self.working_rules_command = working_command
        
        if working_command:
            print(f"✅ Найдена рабочая команда: {' '.join(working_command)}")
        else:
            print("❌ Рабочая команда не найдена")
        
        print("🔥 === КОНЕЦ ДИАГНОСТИКИ === 🔥\n")
        return working_command is not None
    
    def check_firewall_access(self):
        try:
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                  capture_output=True, text=True, timeout=5,
                                  encoding='utf-8', errors='ignore')
            return result.returncode == 0
        except:
            return False
    
    def get_app_path(self, pid):
        try:
            proc = psutil.Process(pid)
            return proc.exe()
        except:
            return None
    
    def create_block_rule(self, app_name, app_path):
        if not self.is_admin():
            raise PermissionError("Требуются права администратора")
        
        if not app_path or not os.path.exists(app_path):
            raise FileNotFoundError(f"Файл приложения не найден: {app_path}")
        
        rule_name = f"{self.rule_prefix}{app_name}"
        
        try:
            commands_to_try = [
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_name}', 'dir=out', 'action=block', f'program={app_path}', 'enable=yes'],
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_name}', 'direction=outbound', 'action=block', f'program={app_path}', 'enable=yes']
            ]
            
            for cmd in commands_to_try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                      encoding='utf-8', errors='ignore')
                
                if result.returncode == 0:
                    self.blocked_apps.add(app_name)
                    return True, "Приложение заблокировано"
            
            return False, "Ошибка создания правила"
                
        except Exception as e:
            return False, f"Ошибка: {str(e)}"
    
    def remove_block_rule(self, app_name):
        if not self.is_admin():
            raise PermissionError("Требуются права администратора")
        
        rule_name = f"{self.rule_prefix}{app_name}"
        
        try:
            commands_to_try = [
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}', 'dir=out']
            ]
            
            for cmd in commands_to_try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                      encoding='utf-8', errors='ignore')
                
                if result.returncode == 0:
                    self.blocked_apps.discard(app_name)
                    return True, "Блокировка снята"
            
            return False, "Ошибка удаления правила"
                
        except Exception as e:
            return False, f"Ошибка: {str(e)}"
    
    def is_app_blocked(self, app_name):
        if app_name in self.blocked_apps:
            return True
        
        blocked_apps = self.get_blocked_apps()
        return app_name in blocked_apps
    
    def get_blocked_apps_with_debug(self):
        blocked = []
        
        if self.working_rules_command:
            cmd = self.working_rules_command
        else:
            emergency_commands = [
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule'],
                ['netsh', 'firewall', 'show', 'config'],
            ]
            
            cmd = None
            for test_cmd in emergency_commands:
                try:
                    result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=15,
                                          encoding='utf-8', errors='ignore')
                    
                    if result.returncode == 0:
                        cmd = test_cmd
                        self.working_rules_command = cmd
                        break
                        
                except Exception:
                    continue
            
            if not cmd:
                return list(self.blocked_apps)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=25,
                                  encoding='utf-8', errors='ignore')
            
            if result.returncode != 0:
                return list(self.blocked_apps)
            
            lines = result.stdout.split('\n')
            
            rule_indicators = [
                'Rule Name:', 'Rule name:', 'Имя правила:', 'Nome da Regra:'
            ]
            
            for line in lines:
                line_clean = line.strip()
                
                for indicator in rule_indicators:
                    if indicator in line_clean:
                        try:
                            parts = line_clean.split(indicator)
                            if len(parts) > 1:
                                rule_name = parts[1].strip()
                                
                                if self.rule_prefix in rule_name:
                                    app_name = rule_name[len(self.rule_prefix):]
                                    if app_name and app_name not in blocked:
                                        blocked.append(app_name)
                        except Exception:
                            pass
                        break
            
            # Альтернативный поиск
            if not blocked:
                for line in lines:
                    if self.rule_prefix in line:
                        parts = line.split(self.rule_prefix)
                        if len(parts) > 1:
                            remaining = parts[1]
                            for delimiter in [' ', '\t', ',', ';', '"', "'", '\n', '\r']:
                                if delimiter in remaining:
                                    app_name = remaining.split(delimiter)[0]
                                    break
                            else:
                                app_name = remaining
                            
                            app_name = app_name.strip('",;\'')
                            
                            if app_name and app_name not in blocked:
                                blocked.append(app_name)
            
            self.blocked_apps = set(blocked)
            return blocked
            
        except Exception:
            return list(self.blocked_apps)
    
    def get_blocked_apps(self):
        return self.get_blocked_apps_with_debug()
    
    def refresh_blocked_status(self):
        self.blocked_apps.clear()
        blocked_apps = self.get_blocked_apps()
        return blocked_apps
    
    def cleanup_rules(self):
        if not self.is_admin():
            return False, "Требуются права администратора"
        
        try:
            blocked_apps = self.get_blocked_apps()
            removed_count = 0
            
            for app_name in blocked_apps:
                success, _ = self.remove_block_rule(app_name)
                if success:
                    removed_count += 1
            
            return True, f"Удалено правил: {removed_count}"
            
        except Exception as e:
            return False, f"Ошибка очистки: {str(e)}"
    
    def manual_test_rule_creation(self, test_app_name="TestApp"):
        if not self.is_admin():
            return False
        
        test_path = "C:\\Windows\\System32\\notepad.exe"
        
        try:
            success, message = self.create_block_rule(test_app_name, test_path)
            
            if success:
                blocked_apps = self.get_blocked_apps()
                test_success = test_app_name in blocked_apps
                
                remove_success, _ = self.remove_block_rule(test_app_name)
                return test_success
                
            return False
                
        except Exception:
            return False

class ToolTip:
    def __init__(self, widget, text='Подсказка'):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.on_enter)
        self.widget.bind("<Leave>", self.on_leave)
        
    def on_enter(self, event=None):
        if self.tooltip_window is not None:
            return
        self.show_tooltip(event)
    
    def on_leave(self, event=None):
        self.hide_tooltip()
    
    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert") if hasattr(self.widget, 'bbox') else (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        
        frame = tk.Frame(self.tooltip_window, bg='#2b2b2b', relief='solid', bd=1)
        frame.pack()
        
        label = tk.Label(frame, text=self.text, bg='#2b2b2b', fg='white',
                        font=('Arial', 9), justify='left', padx=8, pady=5)
        label.pack()
    
    def hide_tooltip(self):
        if self.tooltip_window is not None:
            self.tooltip_window.destroy()
            self.tooltip_window = None

class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("⚡ ТУРБО-Анализатор - Максимальная производительность!")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Данные для мониторинга
        self.traffic_data = deque(maxlen=60)
        self.protocol_stats = defaultdict(int)
        self.connection_stats = defaultdict(int)
        self.bandwidth_data = {'sent': deque(maxlen=60), 'received': deque(maxlen=60)}
        self.time_stamps = deque(maxlen=60)
        
        # Данные приложений
        self.app_traffic = defaultdict(lambda: {'sent': 0, 'received': 0, 'connections': 0, 'last_activity': None})
        self.app_history = defaultdict(lambda: {'sent': deque(maxlen=30), 'received': deque(maxlen=30)})
        self.previous_io_stats = {}
        
        # ⚡ ТУРБО: Накопительные счетчики трафика в мегабайтах
        self.app_total_traffic = defaultdict(lambda: {'sent_mb': 0.0, 'received_mb': 0.0, 'total_mb': 0.0, 'session_start': datetime.now()})
        
        # Флаги состояния
        self.monitoring = False
        self.last_stats = None
        self.auto_update_apps = None
        self.freeze_sort = None
        self.last_sort_order = []
        self.apps_update_counter = 0
        self.apps_tree_tooltip = None
        self.console_log = []
        
        # ⚡ ТУРБО РЕЖИМ: Кэши и флаги производительности
        self.ui_update_cache = {}
        self.last_ui_update = 0
        self.tooltip_last_update = 0
        self.tooltip_delay = 0.5
        self.current_tab = 0
        
        # ⚡ Счетчики для замедления обновлений в турбо режиме
        self.plot_update_counter = 0
        self.table_update_counter = 0
        
        # Менеджер firewall
        self.firewall_manager = FirewallManager()
        self.admin_rights = self.firewall_manager.is_admin()
        self.firewall_available = self.firewall_manager.check_firewall_access()
        
        self.setup_ui()
        self.setup_plots()
        
        # ⚡ Уведомление о турбо режиме
        print("⚡ Анализатор запущен в ТУРБО РЕЖИМЕ!")
        print("🚀 Максимальная производительность и экономия ресурсов")
        print("📱 Автоматическое переключение на вкладку 'Приложения'")
        print("▶️ Автоматический запуск мониторинга через 2 секунды")
        
        # Инициализация таблиц
        self.root.after(1000, self.initialize_tables)
        
        self.monitor_thread = None

    def auto_start_monitoring(self):
        """⚡ Автоматический запуск мониторинга при старте программы"""
        try:
            if not self.monitoring:
                print("⚡ ТУРБО: Автоматический запуск мониторинга...")
                self.start_monitoring()
                print("✅ ТУРБО мониторинг запущен автоматически!")
                
                # Показываем уведомление пользователю
                self.root.after(2000, self.show_auto_start_notification)
        except Exception as e:
            print(f"Ошибка автозапуска мониторинга: {e}")
    
    def show_auto_start_notification(self):
        """Показать уведомление об автозапуске"""
        try:
            messagebox.showinfo("⚡ ТУРБО Автозапуск", 
                              "🚀 Мониторинг запущен автоматически!\n\n"
                              "⚡ ТУРБО РЕЖИМ активен\n"
                              "📱 Вкладка 'Приложения' открыта\n"
                              "🔍 Анализ сетевого трафика начат\n\n"
                              "💡 Для остановки нажмите '⏹️ Стоп'")
        except Exception as e:
            print(f"Ошибка показа уведомления: {e}")

    def switch_to_apps_tab(self):
        """⚡ Переключение на вкладку 'Приложения' при запуске"""
        try:
            # Переключаемся на вкладку "Приложения" (индекс 3)
            self.notebook.select(3)
            self.current_tab = 3
            print("⚡ ТУРБО: Автоматически переключились на вкладку 'Приложения'")
            
            # Обновляем таблицу приложений
            if hasattr(self, 'apps_tree'):
                self.refresh_apps()
                
        except Exception as e:
            print(f"Ошибка переключения на вкладку приложений: {e}")

    def on_tab_changed(self, event):
        """⚡ Отслеживание смены вкладок"""
        try:
            self.current_tab = self.notebook.index(self.notebook.select())
            print(f"⚡ Переключение на вкладку {self.current_tab}")
            
            if self.current_tab == 4:  # Firewall
                self.refresh_firewall_table()
                
        except Exception as e:
            print(f"Ошибка смены вкладки: {e}")

    def initialize_tables(self):
        """Инициализация таблиц после создания UI"""
        try:
            print("⚡ Турбо-инициализация таблиц...")
            if hasattr(self, 'firewall_tree'):
                self.refresh_firewall_table()
            if hasattr(self, 'apps_tree'):
                self.refresh_apps()
            print("✅ Таблицы инициализированы в турбо режиме")
        except Exception as e:
            print(f"❌ Ошибка инициализации таблиц: {e}")
        
    def setup_ui(self):
        # Стиль
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#2b2b2b', foreground='white')
        style.configure('Info.TLabel', font=('Arial', 10), background='#2b2b2b', foreground='white')
        style.configure('Custom.TButton', font=('Arial', 10, 'bold'))
        
        # Основной заголовок
        title_frame = tk.Frame(self.root, bg='#2b2b2b')
        title_frame.pack(fill='x', padx=10, pady=5)
        
        title_label = ttk.Label(title_frame, text="⚡ ТУРБО-Анализатор", style='Title.TLabel')
        title_label.pack(side='left')
        ToolTip(title_label, "⚡ ТУРБО ВЕРСИЯ с автозапуском!\n🚀 Мониторинг включается автоматически\n📱 Вкладка 'Приложения' открывается сразу\n⚡ Максимальная производительность!")
        
        # Кнопки управления
        self.start_btn = ttk.Button(title_frame, text="▶️ Старт", command=self.start_monitoring, style='Custom.TButton')
        self.start_btn.pack(side='right', padx=(0, 5))
        
        self.stop_btn = ttk.Button(title_frame, text="⏹️ Стоп", command=self.stop_monitoring, style='Custom.TButton', state='disabled')
        self.stop_btn.pack(side='right', padx=(0, 5))
        
        self.save_btn = ttk.Button(title_frame, text="💾 Сохранить", command=self.save_report, style='Custom.TButton')
        self.save_btn.pack(side='right', padx=(0, 5))
        
        # ⚡ Кнопка сброса статистики
        self.reset_btn = ttk.Button(title_frame, text="🔄 Сброс", command=self.reset_traffic_stats, style='Custom.TButton')
        self.reset_btn.pack(side='right', padx=(0, 5))
        ToolTip(self.reset_btn, "Сбросить накопительную статистику трафика\nвсех приложений до нуля")
        
        # Информационная панель
        info_frame = tk.Frame(self.root, bg='#363636', relief='raised', bd=1)
        info_frame.pack(fill='x', padx=10, pady=5)
        
        # Первая строка информации
        info_row1 = tk.Frame(info_frame, bg='#363636')
        info_row1.pack(fill='x', padx=5, pady=2)
        
        self.status_label = ttk.Label(info_row1, text="Статус: Остановлен", style='Info.TLabel')
        self.status_label.pack(side='left', padx=10, pady=3)
        
        self.connections_label = ttk.Label(info_row1, text="Соединения: 0", style='Info.TLabel')
        self.connections_label.pack(side='left', padx=10, pady=3)
        
        self.bandwidth_label = ttk.Label(info_row1, text="Скорость: 0 KB/s", style='Info.TLabel')
        self.bandwidth_label.pack(side='left', padx=10, pady=3)
        
        # ⚡ Индикатор турбо режима
        self.perf_label = ttk.Label(info_row1, text="⚡ ТУРБО РЕЖИМ АКТИВЕН", style='Info.TLabel')
        self.perf_label.pack(side='right', padx=10, pady=3)
        
        # Вторая строка - общая статистика трафика
        info_row2 = tk.Frame(info_frame, bg='#363636')
        info_row2.pack(fill='x', padx=5, pady=2)
        
        # ⚡ ОБЩАЯ СТАТИСТИКА ТРАФИКА
        self.total_traffic_label = ttk.Label(info_row2, text="📊 Общий трафик: ↑0.00 MB ↓0.00 MB (Всего: 0.00 MB)", style='Info.TLabel')
        self.total_traffic_label.pack(side='left', padx=10, pady=3)
        
        self.apps_count_label = ttk.Label(info_row2, text="📱 Активных приложений: 0", style='Info.TLabel')
        self.apps_count_label.pack(side='right', padx=10, pady=3)
        
        # Статус прав администратора
        if not self.admin_rights:
            admin_warning = ttk.Label(info_frame, text="⚠️ Нет прав админа", style='Info.TLabel')
            admin_warning.pack(side='right', padx=10, pady=5)
        elif not self.firewall_available:
            firewall_warning = ttk.Label(info_frame, text="⚠️ Firewall недоступен", style='Info.TLabel')
            firewall_warning.pack(side='right', padx=10, pady=5)
        
        # Основная область
        self.main_frame = tk.Frame(self.root, bg='#2b2b2b')
        self.main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Notebook для вкладок
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # ⚡ Привязка смены вкладок
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        # Вкладки
        self.traffic_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.traffic_frame, text="⚡ Трафик (Турбо)")
        
        self.protocol_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.protocol_frame, text="⚡ Протоколы")
        
        self.connections_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.connections_frame, text="⚡ Соединения")
        
        self.apps_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.apps_frame, text="⚡ Приложения (Автозапуск)")
        
        self.firewall_frame = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(self.firewall_frame, text="⚡ Управление доступом")
        
        # ⚡ АВТОМАТИЧЕСКОЕ ПЕРЕКЛЮЧЕНИЕ НА ВКЛАДКУ "ПРИЛОЖЕНИЯ" ПРИ ЗАПУСКЕ
        self.root.after(750, self.switch_to_apps_tab)
        
        # ⚡ АВТОМАТИЧЕСКИЙ ЗАПУСК МОНИТОРИНГА ПРИ СТАРТЕ
        self.root.after(2000, self.auto_start_monitoring)

    def setup_plots(self):
        # График трафика в реальном времени
        self.fig_traffic, self.ax_bandwidth = plt.subplots(1, 1, figsize=(10, 6), facecolor='#2b2b2b')
        self.fig_traffic.patch.set_facecolor('#2b2b2b')
        
        self.ax_bandwidth.set_facecolor('#363636')
        self.ax_bandwidth.set_title('⚡ Пропускная способность (ТУРБО)', color='white', fontsize=12, fontweight='bold')
        self.ax_bandwidth.set_xlabel('Время', color='white')
        self.ax_bandwidth.set_ylabel('KB/s', color='white')
        self.ax_bandwidth.tick_params(colors='white')
        
        plt.tight_layout()
        
        self.canvas_traffic = FigureCanvasTkAgg(self.fig_traffic, self.traffic_frame)
        self.canvas_traffic.get_tk_widget().pack(fill='both', expand=True)
        
        # График протоколов
        self.fig_protocol, self.ax_protocol = plt.subplots(figsize=(8, 6), facecolor='#2b2b2b')
        self.fig_protocol.patch.set_facecolor('#2b2b2b')
        self.ax_protocol.set_facecolor('#363636')
        self.ax_protocol.set_title('⚡ Распределение протоколов (ТУРБО)', color='white', fontsize=12, fontweight='bold')
        
        self.canvas_protocol = FigureCanvasTkAgg(self.fig_protocol, self.protocol_frame)
        self.canvas_protocol.get_tk_widget().pack(fill='both', expand=True)
        
        # Таблицы
        self.setup_connections_table()
        self.setup_apps_table()
        self.setup_firewall_table()
        
    def setup_connections_table(self):
        columns = ('Local Address', 'Remote Address', 'Status', 'PID', 'Process')
        self.connections_tree = ttk.Treeview(self.connections_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.connections_tree.heading(col, text=col)
            self.connections_tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(self.connections_frame, orient='vertical', command=self.connections_tree.yview)
        self.connections_tree.configure(yscrollcommand=scrollbar.set)
        
        self.connections_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
    def setup_apps_table(self):
        """⚡ ТУРБО настройка таблицы активных приложений"""
        control_frame = tk.Frame(self.apps_frame, bg='#2b2b2b')
        control_frame.pack(fill='x', padx=5, pady=5)
        
        apps_title = ttk.Label(control_frame, text="⚡ Приложения (ТУРБО РЕЖИМ)", style='Title.TLabel')
        apps_title.pack(side='left')
        ToolTip(apps_title, "📱 Эта вкладка открывается автоматически при запуске\n▶️ Мониторинг начинается автоматически\n⚡ В турбо режиме показывается до 15 приложений\n📊 Отображается накопительная статистика в МБ\n🔄 Кнопка 'Сброс' обнуляет счетчики")
        
        right_controls = tk.Frame(control_frame, bg='#2b2b2b')
        right_controls.pack(side='right')
        
        self.auto_update_apps = tk.BooleanVar(value=True)
        auto_update_check = ttk.Checkbutton(right_controls, text="Автообновление", 
                                          variable=self.auto_update_apps)
        auto_update_check.pack(side='left', padx=(0, 10))
        
        refresh_btn = ttk.Button(right_controls, text="🔄 Обновить", command=self.refresh_apps, style='Custom.TButton')
        refresh_btn.pack(side='left', padx=(0, 5))
        
        self.freeze_sort = tk.BooleanVar(value=False)
        freeze_btn = ttk.Checkbutton(right_controls, text="Зафиксировать порядок", 
                                   variable=self.freeze_sort)
        freeze_btn.pack(side='left', padx=(5, 0))
        
        apps_columns = ('Приложение', 'PID', 'Отправлено (MB)', 'Получено (MB)', 'Всего (MB)', 'Соединений', 'Последняя активность')
        self.apps_tree = ttk.Treeview(self.apps_frame, columns=apps_columns, show='headings', height=15)
        
        column_widths = {
            'Приложение': 180, 
            'PID': 70, 
            'Отправлено (MB)': 110, 
            'Получено (MB)': 110, 
            'Всего (MB)': 90,
            'Соединений': 90, 
            'Последняя активность': 140
        }
        
        for col in apps_columns:
            self.apps_tree.heading(col, text=col)
            self.apps_tree.column(col, width=column_widths.get(col, 100))
        
        apps_scrollbar_v = ttk.Scrollbar(self.apps_frame, orient='vertical', command=self.apps_tree.yview)
        self.apps_tree.configure(yscrollcommand=apps_scrollbar_v.set)
        
        self.apps_tree.pack(side='left', fill='both', expand=True)
        apps_scrollbar_v.pack(side='right', fill='y')
        
        self.setup_context_menu()
        
        self.apps_tree.bind("<Double-1>", self.on_app_double_click)
        self.apps_tree.bind("<Button-3>", self.show_context_menu)
        self.apps_tree.bind("<Motion>", self.on_apps_tree_motion_turbo)
        self.apps_tree.bind("<Leave>", self.on_apps_tree_leave)
        
        self.apps_tree_tooltip = None

    def setup_firewall_table(self):
        """Настройка таблицы управления firewall"""
        # Заголовок
        header_frame = tk.Frame(self.firewall_frame, bg='#2b2b2b')
        header_frame.pack(fill='x', padx=10, pady=5)
        
        title_label = ttk.Label(header_frame, text="⚡ Управление доступом в интернет (ТУРБО)", style='Title.TLabel')
        title_label.pack(side='left')
        
        status_frame = tk.Frame(header_frame, bg='#2b2b2b')
        status_frame.pack(side='right')
        
        admin_status = "✅ Админ" if self.admin_rights else "❌ Требуются права админа"
        firewall_status = "✅ Доступен" if self.firewall_available else "❌ Недоступен"
        
        admin_label = ttk.Label(status_frame, text=admin_status, style='Info.TLabel')
        admin_label.pack(side='top')
        
        firewall_label = ttk.Label(status_frame, text=f"Firewall: {firewall_status}", style='Info.TLabel')
        firewall_label.pack(side='top')
        
        # Кнопки управления
        controls_frame = tk.Frame(self.firewall_frame, bg='#2b2b2b')
        controls_frame.pack(fill='x', padx=10, pady=5)
        
        refresh_firewall_btn = ttk.Button(controls_frame, text="🔄 Обновить", 
                                        command=self.refresh_firewall_table, style='Custom.TButton')
        refresh_firewall_btn.pack(side='left', padx=(0, 5))
        
        cleanup_btn = ttk.Button(controls_frame, text="🧹 Очистить все", 
                               command=self.cleanup_firewall_rules, style='Custom.TButton')
        cleanup_btn.pack(side='left', padx=(0, 5))
        
        # Диагностические кнопки
        debug_controls_frame = tk.Frame(self.firewall_frame, bg='#2b2b2b')
        debug_controls_frame.pack(fill='x', padx=10, pady=5)
        
        test_firewall_btn = ttk.Button(debug_controls_frame, text="🔧 Тест Firewall", 
                                     command=self.test_firewall_functionality, style='Custom.TButton')
        test_firewall_btn.pack(side='left', padx=(0, 5))
        
        debug_btn = ttk.Button(debug_controls_frame, text="🐛 Диагностика", 
                             command=self.run_firewall_diagnostics, style='Custom.TButton')
        debug_btn.pack(side='left', padx=(0, 5))
        
        # Таблица заблокированных приложений
        firewall_columns = ('Приложение', 'Статус', 'Правило создано', 'Действия')
        self.firewall_tree = ttk.Treeview(self.firewall_frame, columns=firewall_columns, show='headings', height=12)
        
        column_widths = {'Приложение': 300, 'Статус': 150, 'Правило создано': 200, 'Действия': 150}
        for col in firewall_columns:
            self.firewall_tree.heading(col, text=col)
            self.firewall_tree.column(col, width=column_widths.get(col, 100))
        
        firewall_scrollbar_v = ttk.Scrollbar(self.firewall_frame, orient='vertical', command=self.firewall_tree.yview)
        self.firewall_tree.configure(yscrollcommand=firewall_scrollbar_v.set)
        
        self.firewall_tree.pack(side='left', fill='both', expand=True, padx=10, pady=5)
        firewall_scrollbar_v.pack(side='right', fill='y', pady=5)
        
        self.firewall_tree.bind("<Double-1>", self.on_firewall_double_click)
        self.firewall_tree.bind("<Button-3>", self.show_firewall_context_menu)
        
        self.setup_firewall_context_menu()
        
        # Статусная информация
        status_info_frame = tk.Frame(self.firewall_frame, bg='#363636', relief='raised', bd=1)
        status_info_frame.pack(fill='x', padx=10, pady=5)
        
        self.firewall_status_label = ttk.Label(status_info_frame, 
                                             text="⚡ ТУРБО РЕЖИМ: Готов к работе с максимальной производительностью", 
                                             style='Info.TLabel')
        self.firewall_status_label.pack(padx=10, pady=5)

    def setup_context_menu(self):
        """Настройка контекстного меню для приложений"""
        self.context_menu = tk.Menu(self.root, tearoff=0, bg='#3c3c3c', fg='white', 
                                   activebackground='#5c5c5c', activeforeground='white',
                                   font=('Arial', 9))
        self.context_menu.add_command(label="📊 Детали приложения", command=self.show_app_details)
        self.context_menu.add_command(label="🌍 Показать соединения", command=self.show_app_connections)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🚫 Заблокировать интернет", command=self.block_app_internet)
        self.context_menu.add_command(label="✅ Разблокировать интернет", command=self.unblock_app_internet)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🚫 Завершить процесс", command=self.terminate_process)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋 Копировать информацию", command=self.copy_app_info)

    def setup_firewall_context_menu(self):
        """Настройка контекстного меню для таблицы firewall"""
        self.firewall_context_menu = tk.Menu(self.root, tearoff=0, bg='#3c3c3c', fg='white', 
                                           activebackground='#5c5c5c', activeforeground='white',
                                           font=('Arial', 9))
        self.firewall_context_menu.add_command(label="✅ Разблокировать приложение", command=self.unblock_selected_firewall_app)
        self.firewall_context_menu.add_command(label="🔄 Обновить список", command=self.refresh_firewall_table)
        self.firewall_context_menu.add_separator()
        self.firewall_context_menu.add_command(label="📋 Копировать имя", command=self.copy_firewall_app_name)

    def on_apps_tree_motion_turbo(self, event):
        """⚡ ТУРБО обработка движения мыши"""
        current_time = time.time()
        
        if current_time - self.tooltip_last_update < self.tooltip_delay:
            return
        
        self.show_simple_tooltip(event)
        self.tooltip_last_update = current_time

    def show_simple_tooltip(self, event):
        """⚡ ТУРБО tooltip для максимальной производительности"""
        try:
            item = self.apps_tree.identify_row(event.y)
            
            if item:
                values = self.apps_tree.item(item, 'values')
                if values and len(values) >= 7:
                    app_name = values[0]
                    pid = values[1]
                    total_mb = values[4]
                    connections = values[5]
                    
                    clean_app_name = app_name[3:] if app_name.startswith("🚫 ") else app_name[3:] if app_name.startswith("⚡ ") else app_name
                    
                    # Получаем накопительные данные для подробного tooltip
                    total_data = self.app_total_traffic.get(clean_app_name, {})
                    sent_mb = total_data.get('sent_mb', 0)
                    recv_mb = total_data.get('received_mb', 0)
                    
                    tooltip_text = f"""⚡ ТУРБО: {clean_app_name}
PID: {pid} | Соединений: {connections}
↑{sent_mb:.1f}MB ↓{recv_mb:.1f}MB | Всего: {total_mb}MB
ПКМ для действий"""
                    
                    self.show_apps_tree_tooltip(event, tooltip_text)
                else:
                    self.hide_apps_tree_tooltip()
            else:
                self.hide_apps_tree_tooltip()
                
        except Exception:
            self.hide_apps_tree_tooltip()

    # ========== МЕТОДЫ МОНИТОРИНГА ==========

    def get_network_stats(self):
        """⚡ ТУРБО получение статистики сети"""
        try:
            net_io = psutil.net_io_counters()
            # В турбо режиме ограничиваем количество соединений
            connections = psutil.net_connections(kind='inet')[:50]
            
            process_stats = {}
            # В турбо режиме ограничиваем количество процессов
            process_list = list(psutil.process_iter(['pid', 'name']))[:30]
                
            for proc in process_list:
                try:
                    process_stats[proc.info['pid']] = proc.info['name']
                except:
                    continue
                    
            return {
                'net_io': net_io,
                'connections': connections,
                'process_stats': process_stats,
                'timestamp': datetime.now()
            }
        except Exception as e:
            print(f"Ошибка получения статистики: {e}")
            return None

    def get_process_network_activity(self):
        """⚡ ТУРБО получение сетевой активности процессов"""
        active_apps = {}
        current_time = datetime.now()
        
        try:
            # Получаем общую статистику сети для распределения трафика
            net_io = psutil.net_io_counters()
            
            connections = psutil.net_connections(kind='inet')
            process_connections = defaultdict(list)
            
            # В турбо режиме значительно ограничиваем количество соединений
            max_connections = 100
            
            for conn in connections[:max_connections]:
                if conn.pid:
                    process_connections[conn.pid].append(conn)
            
            # Вычисляем изменение общего сетевого трафика
            total_net_sent_diff = 0
            total_net_recv_diff = 0
            
            if hasattr(self, 'last_net_io'):
                total_net_sent_diff = max(0, net_io.bytes_sent - self.last_net_io.bytes_sent)
                total_net_recv_diff = max(0, net_io.bytes_recv - self.last_net_io.bytes_recv)
            
            self.last_net_io = net_io
            
            # Подсчитываем общее количество активных интернет-соединений
            total_active_connections = 0
            active_process_connections = {}
            
            for pid, conns in process_connections.items():
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                    
                    internet_conns = []
                    for conn in conns:
                        # Расширенная проверка интернет-соединений
                        is_internet = False
                        
                        if conn.raddr:  # Есть удаленный адрес
                            remote_ip = conn.raddr.ip
                            
                            # Исключаем только явно локальные адреса
                            if not (remote_ip.startswith('127.') or 
                                   remote_ip.startswith('0.') or
                                   remote_ip == '::1' or
                                   remote_ip.startswith('fe80:')):
                                
                                # Включаем все статусы соединений, не только ESTABLISHED
                                if conn.status in ['ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'CLOSE_WAIT', 'TIME_WAIT']:
                                    is_internet = True
                                    
                                # Для Download Manager'ов учитываем даже LISTEN соединения на внешних IP
                                elif (conn.status == 'LISTEN' and 
                                      proc_name.lower() in ['idman.exe', 'fdm.exe', 'eagleget.exe', 'jdownloader.exe']):
                                    is_internet = True
                        
                        # Также учитываем исходящие соединения без удаленного адреса
                        elif (conn.laddr and conn.status in ['SYN_SENT', 'ESTABLISHED'] and
                              not conn.laddr.ip.startswith('127.')):
                            is_internet = True
                            
                        if is_internet:
                            internet_conns.append(conn)
                    
                    if internet_conns:
                        active_process_connections[pid] = {
                            'name': proc_name,
                            'connections': len(internet_conns)
                        }
                        total_active_connections += len(internet_conns)
                        
                        # Отладочная информация для соединений
                        if proc_name.lower() in ['idman.exe', 'fdm.exe', 'chrome.exe', 'firefox.exe']:
                            print(f"🔗 {proc_name}: найдено {len(internet_conns)} интернет-соединений")
                            for i, conn in enumerate(internet_conns[:3]):  # Показываем первые 3
                                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                                print(f"  └─ {i+1}. {conn.status} -> {remote}")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Распределяем общий сетевой трафик с умной логикой
            total_raw_weight = 0
            app_weights = {}
            high_traffic_apps = []
            
            # ЭТАП 1: Анализируем активность приложений
            for pid, proc_info in active_process_connections.items():
                proc_name = proc_info['name']
                connection_count = proc_info['connections']
                
                # Определяем тип приложения и его потенциальную активность
                app_type = "normal"
                base_priority = 1.0
                
                if proc_name.lower() in ['idman.exe', 'fdm.exe', 'eagleget.exe', 'jdownloader.exe', 'xdm.exe']:
                    app_type = "download_manager"
                    base_priority = 50.0  # Очень высокий приоритет
                elif proc_name.lower() in ['torrent', 'utorrent.exe', 'bittorrent.exe', 'qbittorrent.exe']:
                    app_type = "torrent"
                    base_priority = 30.0
                elif proc_name.lower() in ['steam.exe', 'epicgameslauncher.exe', 'battle.net.exe']:
                    app_type = "game_launcher"
                    base_priority = 20.0
                elif proc_name.lower() in ['chrome.exe', 'firefox.exe', 'edge.exe', 'opera.exe', 'msedge.exe']:
                    app_type = "browser"
                    base_priority = 8.0
                elif proc_name.lower() in ['vlc.exe', 'potplayer.exe', 'kmplayer.exe']:
                    app_type = "video_player"
                    base_priority = 15.0
                elif proc_name.lower() in ['discord.exe', 'telegram.exe', 'skype.exe', 'zoom.exe']:
                    app_type = "messenger"
                    base_priority = 2.0
                
                # Вычисляем активность приложения
                activity_score = connection_count * base_priority
                
                # Особая логика для Download Manager'ов
                if app_type == "download_manager" and connection_count >= 2:
                    # Если Download Manager активен (2+ соединения), он получает 80-90% трафика
                    activity_score = connection_count * 1000  # Огромный приоритет
                    high_traffic_apps.append((proc_name, pid, activity_score))
                    print(f"🚨 АКТИВНЫЙ DOWNLOAD MANAGER: {proc_name} с {connection_count} соединениями!")
                
                elif app_type == "torrent" and connection_count >= 3:
                    # Торренты с много соединений тоже получают высокий приоритет
                    activity_score = connection_count * 500
                    high_traffic_apps.append((proc_name, pid, activity_score))
                    print(f"🚨 АКТИВНЫЙ ТОРРЕНТ: {proc_name} с {connection_count} соединениями!")
                
                elif app_type == "browser" and connection_count >= 5:
                    # Браузеры с много соединений (стриминг видео)
                    activity_score = connection_count * 100
                    high_traffic_apps.append((proc_name, pid, activity_score))
                    print(f"🌐 АКТИВНЫЙ БРАУЗЕР: {proc_name} с {connection_count} соединениями!")
                
                app_weights[pid] = {
                    'name': proc_name,
                    'connections': connection_count,
                    'activity_score': activity_score,
                    'app_type': app_type
                }
                total_raw_weight += activity_score
            
            # ЭТАП 2: Особое распределение если есть высоко-активные приложения
            if high_traffic_apps and (total_net_sent_diff > 1024 or total_net_recv_diff > 1024):
                # Сортируем по активности (самые активные первыми)
                high_traffic_apps.sort(key=lambda x: x[2], reverse=True)
                most_active_app = high_traffic_apps[0]
                
                print(f"🎯 ОСНОВНОЙ ПОТРЕБИТЕЛЬ ТРАФИКА: {most_active_app[0]}")
                
                # Определяем долю основного приложения в зависимости от типа
                main_app_info = app_weights[most_active_app[1]]
                
                if main_app_info['app_type'] == "download_manager":
                    # Download Manager'ы получают 95% трафика!
                    main_app_share = 0.95
                    remaining_share = 0.05
                    print(f"🚨 DOWNLOAD MANAGER получает 95% трафика!")
                elif main_app_info['app_type'] == "torrent":
                    # Торренты получают 90%
                    main_app_share = 0.90
                    remaining_share = 0.10
                elif main_app_info['app_type'] == "game_launcher":
                    # Игровые лаунчеры получают 85%
                    main_app_share = 0.85
                    remaining_share = 0.15
                else:
                    # Остальные получают 80%
                    main_app_share = 0.80
                    remaining_share = 0.20
                
                distributed_traffic = {}
                
                # Даем основную долю самому активному приложению
                main_pid = most_active_app[1]
                distributed_traffic[main_pid] = main_app_share
                
                # Остальные приложения получают крохи
                other_apps = [pid for pid in app_weights.keys() if pid != main_pid]
                if other_apps and remaining_share > 0:
                    # Очень маленькая доля для остальных
                    crumb_per_app = remaining_share / len(other_apps)
                    for pid in other_apps:
                        distributed_traffic[pid] = crumb_per_app
                
            else:
                # ЭТАП 3: Обычное пропорциональное распределение
                distributed_traffic = {}
                if total_raw_weight > 0:
                    for pid, weight_info in app_weights.items():
                        exact_proportion = weight_info['activity_score'] / total_raw_weight
                        distributed_traffic[pid] = exact_proportion
            
            # ЭТАП 4: Применяем распределение трафика
            for pid, proportion in distributed_traffic.items():
                weight_info = app_weights[pid]
                proc_name = weight_info['name']
                connection_count = weight_info['connections']
                
                # Распределяем трафик точно по пропорции
                sent_bytes = total_net_sent_diff * proportion
                recv_bytes = total_net_recv_diff * proportion
                
                sent_kb = sent_bytes / 1024
                recv_kb = recv_bytes / 1024
                
                # ⚡ НАКАПЛИВАЕМ ДАННЫЕ В МЕГАБАЙТАХ
                sent_mb = sent_kb / 1024
                recv_mb = recv_kb / 1024
                
                # Добавляем к накопительным счетчикам
                self.app_total_traffic[proc_name]['sent_mb'] += sent_mb
                self.app_total_traffic[proc_name]['received_mb'] += recv_mb
                self.app_total_traffic[proc_name]['total_mb'] = (
                    self.app_total_traffic[proc_name]['sent_mb'] + 
                    self.app_total_traffic[proc_name]['received_mb']
                )
                
                self.app_traffic[proc_name]['sent'] = sent_kb
                self.app_traffic[proc_name]['received'] = recv_kb
                self.app_traffic[proc_name]['connections'] = connection_count
                self.app_traffic[proc_name]['last_activity'] = current_time
                self.app_traffic[proc_name]['pid'] = pid
                
                active_apps[proc_name] = {
                    'pid': pid,
                    'connections': connection_count,
                    'last_activity': current_time,
                    'sent': sent_kb,
                    'received': recv_kb,
                    # Добавляем накопительные данные в MB
                    'total_sent_mb': self.app_total_traffic[proc_name]['sent_mb'],
                    'total_received_mb': self.app_total_traffic[proc_name]['received_mb'],
                    'total_mb': self.app_total_traffic[proc_name]['total_mb']
                }
                
                # Отладочная информация с пропорциями
                if recv_mb > 0.1 or sent_mb > 0.1:  # Если больше 0.1 MB
                    print(f"⚡ {proc_name}: +{recv_mb:.2f}MB получено, +{sent_mb:.2f}MB отправлено "
                          f"({proportion*100:.1f}% трафика, {connection_count} соед.)")
            
            # ЭТАП 5: Проверяем что суммы сходятся
            if total_net_sent_diff > 1024 or total_net_recv_diff > 1024:  # Если есть значительный трафик
                distributed_sent = sum(data.get('sent', 0) for data in active_apps.values()) / 1024  # MB
                distributed_recv = sum(data.get('received', 0) for data in active_apps.values()) / 1024  # MB
                
                system_sent_mb = total_net_sent_diff / 1024 / 1024
                system_recv_mb = total_net_recv_diff / 1024 / 1024
                
                print(f"📊 ПРОВЕРКА: Системный трафик: ↑{system_sent_mb:.2f}MB ↓{system_recv_mb:.2f}MB")
                print(f"📊 ПРОВЕРКА: Распределенный: ↑{distributed_sent:.2f}MB ↓{distributed_recv:.2f}MB")
                if high_traffic_apps:
                    main_app = high_traffic_apps[0][0]
                    main_recv = active_apps.get(main_app, {}).get('received', 0) / 1024
                    print(f"🎯 ОСНОВНОЙ: {main_app} получил {main_recv:.2f}MB ({main_recv/max(system_recv_mb, 0.001)*100:.1f}%)")
            
            return active_apps
            
        except Exception as e:
            print(f"Ошибка получения активности приложений: {e}")
            return {}

    def calculate_bandwidth(self, current_stats):
        """Расчет пропускной способности"""
        if self.last_stats is None:
            self.last_stats = current_stats
            return 0, 0
            
        time_diff = (current_stats['timestamp'] - self.last_stats['timestamp']).total_seconds()
        if time_diff <= 0:
            return 0, 0
            
        bytes_sent_diff = current_stats['net_io'].bytes_sent - self.last_stats['net_io'].bytes_sent
        bytes_recv_diff = current_stats['net_io'].bytes_recv - self.last_stats['net_io'].bytes_recv
        
        sent_rate = (bytes_sent_diff / time_diff) / 1024
        recv_rate = (bytes_recv_diff / time_diff) / 1024
        
        self.last_stats = current_stats
        return sent_rate, recv_rate

    def update_data(self):
        """⚡ ТУРБО обновление данных мониторинга"""
        while self.monitoring:
            stats = self.get_network_stats()
            if stats:
                sent_rate, recv_rate = self.calculate_bandwidth(stats)
                
                current_time = datetime.now().strftime('%H:%M:%S')
                self.time_stamps.append(current_time)
                self.bandwidth_data['sent'].append(sent_rate)
                self.bandwidth_data['received'].append(recv_rate)
                
                active_connections = len([c for c in stats['connections'] if c.status == 'ESTABLISHED'])
                
                for conn in stats['connections']:
                    if conn.type == socket.SOCK_STREAM:
                        self.protocol_stats['TCP'] += 1
                    elif conn.type == socket.SOCK_DGRAM:
                        self.protocol_stats['UDP'] += 1
                
                active_apps = self.get_process_network_activity()
                
                self.root.after(0, self.update_ui_turbo, stats, sent_rate, recv_rate, active_connections, active_apps)
                
            # В турбо режиме делаем паузы больше
            time.sleep(3)

    def update_ui_turbo(self, stats, sent_rate, recv_rate, active_connections, active_apps):
        """⚡ ТУРБО обновление интерфейса"""
        current_time = time.time()
        
        # В турбо режиме обновляем реже
        min_update_interval = 3
        if current_time - self.last_ui_update < min_update_interval:
            return
        
        # Безопасное обновление элементов интерфейса
        if hasattr(self, 'status_label'):
            status_text = f"Статус: {'⚡ТУРБО Мониторинг' if self.monitoring else 'Остановлен'}"
            self.status_label.config(text=status_text)
        if hasattr(self, 'connections_label'):
            self.connections_label.config(text=f"Соединения: {active_connections}")
        if hasattr(self, 'bandwidth_label'):
            self.bandwidth_label.config(text=f"↑{sent_rate:.1f} KB/s ↓{recv_rate:.1f} KB/s")
        
        # ⚡ ВЫЧИСЛЯЕМ ОБЩУЮ СТАТИСТИКУ ТРАФИКА
        total_sent_mb = 0.0
        total_received_mb = 0.0
        total_apps_count = 0
        
        # Суммируем трафик всех приложений
        for app_name, traffic_data in self.app_total_traffic.items():
            total_sent_mb += traffic_data.get('sent_mb', 0)
            total_received_mb += traffic_data.get('received_mb', 0)
            total_apps_count += 1
        
        total_mb = total_sent_mb + total_received_mb
        
        # Обновляем отображение общей статистики
        if hasattr(self, 'total_traffic_label'):
            self.total_traffic_label.config(
                text=f"📊 Общий трафик: ↑{total_sent_mb:.2f} MB ↓{total_received_mb:.2f} MB (Всего: {total_mb:.2f} MB)"
            )
        
        if hasattr(self, 'apps_count_label'):
            active_now = len([app for app in active_apps if active_apps[app]['connections'] > 0])
            self.apps_count_label.config(text=f"📱 Активных: {active_now}/{total_apps_count}")
        
        # ⚡ Обновляем только активную вкладку в турбо режиме
        if self.current_tab == 0:  # Трафик
            self.plot_update_counter += 1
            if self.plot_update_counter >= 4:
                self.update_traffic_plot()
                self.plot_update_counter = 0
                
        elif self.current_tab == 1:  # Протоколы
            self.update_protocol_plot()
            
        elif self.current_tab == 2:  # Соединения
            self.table_update_counter += 1
            if self.table_update_counter >= 6:
                self.update_connections_table(stats)
                self.table_update_counter = 0
        
        elif self.current_tab == 3:  # Приложения
            if hasattr(self, 'auto_update_apps') and self.auto_update_apps and self.auto_update_apps.get():
                self.apps_update_counter += 1
                if self.apps_update_counter >= 8:
                    self.update_apps_table(active_apps)
                    self.apps_update_counter = 0
        
        self.last_ui_update = current_time

    def update_traffic_plot(self):
        """⚡ ТУРБО обновление графика трафика"""
        if not hasattr(self, 'ax_bandwidth') or not hasattr(self, 'canvas_traffic'):
            return
            
        if len(self.bandwidth_data['sent']) > 1:
            self.ax_bandwidth.clear()
            self.ax_bandwidth.set_facecolor('#363636')
            
            self.ax_bandwidth.plot(range(len(self.bandwidth_data['sent'])), self.bandwidth_data['sent'], 
                                 'r-', label='Отправлено', linewidth=1)
            self.ax_bandwidth.plot(range(len(self.bandwidth_data['received'])), self.bandwidth_data['received'], 
                                 'b-', label='Получено', linewidth=1)
            self.ax_bandwidth.set_title('⚡ ТУРБО: Пропускная способность', color='white', fontweight='bold')
            
            self.ax_bandwidth.set_ylabel('KB/s', color='white')
            self.ax_bandwidth.tick_params(colors='white')
            self.ax_bandwidth.legend()
            
            self.canvas_traffic.draw()

    def update_protocol_plot(self):
        """⚡ ТУРБО обновление графика протоколов"""
        if not hasattr(self, 'ax_protocol') or not hasattr(self, 'canvas_protocol'):
            return
            
        if self.protocol_stats:
            self.ax_protocol.clear()
            self.ax_protocol.set_facecolor('#363636')
            
            protocols = list(self.protocol_stats.keys())
            values = list(self.protocol_stats.values())
            colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#ffeaa7']
            
            self.ax_protocol.pie(values, labels=protocols, colors=colors[:len(protocols)])
            self.ax_protocol.set_title('⚡ ТУРБО: Протоколы', color='white', fontweight='bold')
            
            self.canvas_protocol.draw()

    def update_connections_table(self, stats):
        """⚡ ТУРБО обновление таблицы соединений"""
        if not hasattr(self, 'connections_tree'):
            return
        
        current_count = len(self.connections_tree.get_children())
        # В турбо режиме ограничиваем количество записей
        max_records = 25
        new_count = min(len(stats['connections']), max_records)
        
        if abs(current_count - new_count) > 5:
            for item in self.connections_tree.get_children():
                self.connections_tree.delete(item)
            
            for conn in stats['connections'][:max_records]:
                try:
                    local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    status = conn.status
                    pid = conn.pid if conn.pid else "N/A"
                    process_name = stats['process_stats'].get(conn.pid, "Unknown") if conn.pid else "N/A"
                    
                    self.connections_tree.insert('', 'end', values=(local_addr, remote_addr, status, pid, process_name))
                except:
                    continue

    def update_apps_table(self, active_apps):
        """⚡ ТУРБО обновление таблицы активных приложений"""
        # Сохраняем выделение
        selected_items = self.apps_tree.selection()
        selected_values = []
        for item in selected_items:
            try:
                values = self.apps_tree.item(item, 'values')
                if values:
                    selected_values.append(values[0])
            except:
                pass
        
        # Очищаем таблицу
        for item in self.apps_tree.get_children():
            self.apps_tree.delete(item)
        
        all_apps = {}
        
        # Объединяем данные с накопительными счетчиками
        for app_name, data in active_apps.items():
            all_apps[app_name] = {
                'pid': data['pid'],
                'sent': data.get('sent', 0),
                'received': data.get('received', 0),
                'connections': data['connections'],
                'last_activity': data['last_activity'],
                'total_sent_mb': data.get('total_sent_mb', 0),
                'total_received_mb': data.get('total_received_mb', 0),
                'total_mb': data.get('total_mb', 0)
            }
        
        # Добавляем данные из исторических записей для неактивных приложений
        for app_name, traffic_data in self.app_traffic.items():
            if app_name not in all_apps:
                total_data = self.app_total_traffic.get(app_name, {})
                all_apps[app_name] = {
                    'pid': traffic_data.get('pid', 'N/A'),
                    'sent': traffic_data['sent'],
                    'received': traffic_data['received'],
                    'connections': traffic_data['connections'],
                    'last_activity': traffic_data['last_activity'],
                    'total_sent_mb': total_data.get('sent_mb', 0),
                    'total_received_mb': total_data.get('received_mb', 0),
                    'total_mb': total_data.get('total_mb', 0)
                }
        
        # Сортировка по общему объему трафика (больше трафика = выше в списке)
        sorted_apps = sorted(all_apps.items(), 
                           key=lambda x: x[1]['total_mb'] + x[1]['connections'], 
                           reverse=True)
        
        # ⚡ В турбо режиме ограничиваем количество записей
        max_apps = 15
        
        for app_name, data in sorted_apps[:max_apps]:
            try:
                pid = data['pid']
                # Отображаем накопительные данные в мегабайтах
                sent_mb = f"{data['total_sent_mb']:.2f}"
                recv_mb = f"{data['total_received_mb']:.2f}"
                total_mb = f"{data['total_mb']:.2f}"
                connections = data['connections']
                last_activity = data['last_activity'].strftime('%H:%M:%S') if data['last_activity'] else "N/A"
                
                # Проверяем статус блокировки
                is_blocked = self.firewall_manager.is_app_blocked(app_name)
                
                if is_blocked:
                    tag = 'blocked_app'
                    display_name = f"🚫 {app_name}"
                else:
                    display_name = f"⚡ {app_name}"
                    # Определяем уровень активности по общему трафику
                    if data['total_mb'] > 10 or connections > 5:
                        tag = 'high_activity'
                    elif data['total_mb'] > 1 or connections > 2:
                        tag = 'medium_activity'
                    elif connections > 0 or data['total_mb'] > 0:
                        tag = 'low_activity'
                    else:
                        tag = 'no_activity'
                
                item = self.apps_tree.insert('', 'end', 
                                    values=(display_name, pid, sent_mb, recv_mb, total_mb, connections, last_activity),
                                    tags=(tag,))
                
                if app_name in selected_values:
                    self.apps_tree.selection_add(item)
                    
            except Exception as e:
                print(f"Ошибка добавления приложения {app_name}: {e}")
                continue
        
        # Настройка цветов для турбо режима
        self.apps_tree.tag_configure('high_activity', background='#ff4757', foreground='white')
        self.apps_tree.tag_configure('medium_activity', background='#ffa502', foreground='white') 
        self.apps_tree.tag_configure('low_activity', background='#2ed573', foreground='white')
        self.apps_tree.tag_configure('no_activity', background='#747d8c', foreground='white')
        self.apps_tree.tag_configure('blocked_app', background='#8b0000', foreground='white')

    # ========== ОБРАБОТЧИКИ СОБЫТИЙ ==========

    def show_apps_tree_tooltip(self, event, text):
        """Показать подсказку для таблицы приложений"""
        self.hide_apps_tree_tooltip()
        
        x = self.apps_tree.winfo_rootx() + event.x + 15
        y = self.apps_tree.winfo_rooty() + event.y + 15
        
        self.apps_tree_tooltip = tk.Toplevel(self.root)
        self.apps_tree_tooltip.wm_overrideredirect(True)
        self.apps_tree_tooltip.wm_geometry(f"+{x}+{y}")
        
        frame = tk.Frame(self.apps_tree_tooltip, bg='#1a1a1a', relief='solid', bd=2)
        frame.pack()
        
        label = tk.Label(frame, text=text, bg='#1a1a1a', fg='#ffffff',
                        font=('Consolas', 9), justify='left', padx=12, pady=8)
        label.pack()

    def hide_apps_tree_tooltip(self):
        """Скрыть подсказку для таблицы приложений"""
        if self.apps_tree_tooltip is not None:
            self.apps_tree_tooltip.destroy()
            self.apps_tree_tooltip = None

    def on_apps_tree_leave(self, event):
        """Обработка выхода мыши из таблицы приложений"""
        self.hide_apps_tree_tooltip()

    def show_context_menu(self, event):
        """Показать контекстное меню"""
        try:
            self.hide_apps_tree_tooltip()
            
            item = self.apps_tree.identify_row(event.y)
            
            if item:
                self.apps_tree.selection_set(item)
                self.apps_tree.focus(item)
                self.context_menu.post(event.x_root, event.y_root)
            else:
                self.apps_tree.selection_remove(self.apps_tree.selection())
        except Exception as e:
            print(f"Ошибка показа контекстного меню: {e}")

    def show_firewall_context_menu(self, event):
        """Показать контекстное меню для таблицы firewall"""
        try:
            if not hasattr(self, 'firewall_tree') or not hasattr(self, 'firewall_context_menu'):
                return
                
            item = self.firewall_tree.identify_row(event.y)
            
            if item:
                values = self.firewall_tree.item(item, 'values')
                if values and values[0] != "⚡ ТУРБО: Нет заблокированных приложений":
                    self.firewall_tree.selection_set(item)
                    self.firewall_tree.focus(item)
                    self.firewall_context_menu.post(event.x_root, event.y_root)
        except Exception as e:
            print(f"Ошибка показа контекстного меню firewall: {e}")

    def on_app_double_click(self, event):
        """Обработка двойного клика по приложению"""
        if not hasattr(self, 'apps_tree'):
            return
            
        item = self.apps_tree.identify_row(event.y)
        if item:
            self.apps_tree.selection_set(item)
            self.apps_tree.focus(item)
            self.show_app_details()

    def on_firewall_double_click(self, event):
        """Обработка двойного клика в таблице firewall"""
        if not hasattr(self, 'firewall_tree'):
            return
            
        item = self.firewall_tree.identify_row(event.y)
        if item:
            values = self.firewall_tree.item(item, 'values')
            if values and values[0] != "⚡ ТУРБО: Нет заблокированных приложений":
                app_name = values[0]
                
                result = messagebox.askyesno("Разблокировка", 
                                           f"Разблокировать приложение {app_name}?")
                if result:
                    try:
                        success, message = self.firewall_manager.remove_block_rule(app_name)
                        if success:
                            messagebox.showinfo("Успех", f"Приложение {app_name} разблокировано!")
                            self.refresh_firewall_table()
                            self.refresh_apps()
                        else:
                            messagebox.showerror("Ошибка", f"Не удалось разблокировать:\n{message}")
                    except Exception as e:
                        messagebox.showerror("Ошибка", f"Ошибка: {str(e)}")

    # ========== ДЕЙСТВИЯ С ПРИЛОЖЕНИЯМИ ==========

    def get_selected_app_info(self):
        """Получить информацию о выбранном приложении"""
        try:
            if not hasattr(self, 'apps_tree'):
                messagebox.showwarning("Предупреждение", "Интерфейс еще не готов")
                return None
                
            selection = self.apps_tree.selection()
            if not selection:
                messagebox.showwarning("Предупреждение", "Пожалуйста, выберите приложение")
                return None
                
            item = selection[0]
            values = self.apps_tree.item(item, 'values')
            
            if not values or len(values) < 7:
                messagebox.showwarning("Предупреждение", "Не удалось получить информацию о приложении")
                return None
            
            app_name = values[0]
            
            # Убираем все возможные префиксы
            for prefix in ["🚫 ", "⚡ "]:
                if app_name.startswith(prefix):
                    app_name = app_name[len(prefix):]
                    break
                
            return {
                'name': app_name,
                'pid': values[1],
                'sent': values[2],      # Отправлено MB
                'received': values[3],  # Получено MB
                'total': values[4],     # Всего MB
                'connections': values[5],
                'last_activity': values[6]
            }
        except (IndexError, ValueError) as e:
            print(f"Ошибка получения информации о приложении: {e}")
            messagebox.showerror("Ошибка", f"Не удалось получить информацию о приложении: {e}")
            return None

    def get_selected_firewall_app(self):
        """Получить информацию о выбранном приложении из таблицы firewall"""
        try:
            if not hasattr(self, 'firewall_tree'):
                return None
                
            selection = self.firewall_tree.selection()
            if not selection:
                return None
                
            item = selection[0]
            values = self.firewall_tree.item(item, 'values')
            
            if not values or len(values) < 1:
                return None
            
            app_name = values[0]
            if app_name == "⚡ ТУРБО: Нет заблокированных приложений":
                return None
                
            return {
                'name': app_name,
                'status': values[1] if len(values) > 1 else "",
                'created_time': values[2] if len(values) > 2 else "",
                'actions': values[3] if len(values) > 3 else ""
            }
        except (IndexError, ValueError) as e:
            print(f"Ошибка получения информации о заблокированном приложении: {e}")
            return None

    def show_app_details(self):
        """Показать детальную информацию о приложении"""
        app_info = self.get_selected_app_info()
        if not app_info:
            return
        
        # Получаем путь к файлу приложения
        app_path = "Недоступен"
        try:
            if app_info['pid'] != 'N/A':
                pid = int(app_info['pid'])
                app_path = self.firewall_manager.get_app_path(pid)
                if not app_path:
                    app_path = "Недоступен"
        except (ValueError, TypeError, Exception):
            app_path = "Недоступен"
            
        # Проверяем статус блокировки
        is_blocked = self.firewall_manager.is_app_blocked(app_info['name'])
        block_status = "🚫 ЗАБЛОКИРОВАН" if is_blocked else "✅ Доступ разрешен"
        
        # Получаем накопительные данные
        total_data = self.app_total_traffic.get(app_info['name'], {})
        total_sent_mb = total_data.get('sent_mb', 0)
        total_received_mb = total_data.get('received_mb', 0)
        total_mb = total_data.get('total_mb', 0)
        session_start = total_data.get('session_start', datetime.now())
        
        # Вычисляем время работы
        session_duration = datetime.now() - session_start
        hours = int(session_duration.total_seconds() // 3600)
        minutes = int((session_duration.total_seconds() % 3600) // 60)
        duration_str = f"{hours}ч {minutes}м" if hours > 0 else f"{minutes}м"
            
        detail_text = f"⚡ ТУРБО РЕЖИМ: Детали приложения\n\n"
        detail_text += f"Приложение: {app_info['name']}\n"
        detail_text += f"PID: {app_info['pid']}\n"
        detail_text += f"Путь к файлу: {app_path}\n"
        detail_text += f"Статус интернета: {block_status}\n"
        detail_text += f"Время работы: {duration_str}\n\n"
        detail_text += f"📡 Общий трафик за сессию:\n"
        detail_text += f"Отправлено: {total_sent_mb:.2f} MB\n"
        detail_text += f"Получено: {total_received_mb:.2f} MB\n"
        detail_text += f"Всего: {total_mb:.2f} MB\n\n"
        detail_text += f"📊 Текущая активность:\n"
        detail_text += f"Соединений: {app_info['connections']}\n"
        detail_text += f"Последняя активность: {app_info['last_activity']}"
        
        messagebox.showinfo("⚡ Детали приложения", detail_text)

    def show_app_connections(self):
        """Показать соединения приложения"""
        app_info = self.get_selected_app_info()
        if app_info:
            conn_text = f"⚡ ТУРБО: Соединения для {app_info['name']}: {app_info['connections']}"
            messagebox.showinfo("Соединения", conn_text)

    def terminate_process(self):
        """Завершить процесс"""
        app_info = self.get_selected_app_info()
        if not app_info:
            return
        
        # Проверяем PID
        if app_info['pid'] == 'N/A':
            messagebox.showwarning("Предупреждение", "PID процесса недоступен")
            return
            
        try:
            pid = int(app_info['pid'])
        except (ValueError, TypeError):
            messagebox.showerror("Ошибка", "Некорректный PID процесса")
            return
        
        # Получаем информацию о процессе
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc_status = proc.status()
            
            # Предупреждение для критических процессов
            critical_processes = ['explorer.exe', 'winlogon.exe', 'csrss.exe', 'dwm.exe', 
                                'lsass.exe', 'services.exe', 'smss.exe', 'wininit.exe']
            
            if proc_name.lower() in [p.lower() for p in critical_processes]:
                result = messagebox.askyesno("⚠️ КРИТИЧЕСКИЙ ПРОЦЕСС", 
                                           f"⚠️ {proc_name} - это критический системный процесс!\n\n"
                                           f"Его завершение может привести к нестабильности системы.\n\n"
                                           f"Вы ДЕЙСТВИТЕЛЬНО хотите завершить этот процесс?",
                                           icon='warning')
                if not result:
                    return
            else:
                result = messagebox.askyesno("Подтверждение завершения", 
                                           f"⚡ ТУРБО: Завершить процесс?\n\n"
                                           f"Процесс: {proc_name}\n"
                                           f"PID: {pid}\n"
                                           f"Статус: {proc_status}\n\n"
                                           f"Будут использованы все доступные методы завершения!")
                if not result:
                    return
                    
        except psutil.NoSuchProcess:
            messagebox.showerror("Ошибка", f"Процесс с PID {pid} не найден")
            return
        except psutil.AccessDenied:
            messagebox.showerror("Ошибка", f"Недостаточно прав для доступа к процессу {pid}")
            return
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка получения информации о процессе: {e}")
            return
        
        # Создаем окно прогресса
        progress_window = self.show_progress_window(f"⚡ ТУРБО завершение процесса {proc_name}...")
        
        success = False
        method_used = ""
        
        try:
            # МЕТОД 1: Мягкое завершение через psutil
            print(f"⚡ МЕТОД 1: Мягкое завершение процесса {proc_name} (PID: {pid})")
            try:
                proc.terminate()
                proc.wait(timeout=2)
                if not proc.is_running():
                    success = True
                    method_used = "мягкое завершение (terminate)"
                    print(f"✅ Успех методом 1")
            except psutil.TimeoutExpired:
                print(f"⏰ Метод 1 не сработал за 2 сек")
            except Exception as e:
                print(f"❌ Метод 1 ошибка: {e}")
            
            # МЕТОД 2: Принудительное завершение через psutil
            if not success:
                print(f"⚡ МЕТОД 2: Принудительное завершение")
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                    if not proc.is_running():
                        success = True
                        method_used = "принудительное завершение (kill)"
                        print(f"✅ Успех методом 2")
                except psutil.TimeoutExpired:
                    print(f"⏰ Метод 2 не сработал за 2 сек")
                except Exception as e:
                    print(f"❌ Метод 2 ошибка: {e}")
            
            # МЕТОД 3: Системная команда taskkill /F
            if not success:
                print(f"⚡ МЕТОД 3: Системная команда taskkill /F")
                try:
                    result = subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                                          capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        # Проверяем, что процесс действительно завершен
                        time.sleep(0.5)
                        try:
                            test_proc = psutil.Process(pid)
                            if not test_proc.is_running():
                                success = True
                                method_used = "системная команда taskkill"
                                print(f"✅ Успех методом 3")
                        except psutil.NoSuchProcess:
                            success = True
                            method_used = "системная команда taskkill"
                            print(f"✅ Успех методом 3 (процесс не найден)")
                    else:
                        print(f"❌ Метод 3 ошибка: {result.stderr}")
                        
                except subprocess.TimeoutExpired:
                    print(f"⏰ Метод 3 превысил время ожидания")
                except Exception as e:
                    print(f"❌ Метод 3 ошибка: {e}")
            
            # МЕТОД 4: Завершение по имени процесса
            if not success:
                print(f"⚡ МЕТОД 4: Завершение по имени процесса")
                try:
                    result = subprocess.run(['taskkill', '/F', '/IM', proc_name], 
                                          capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        # Проверяем, что наш процесс завершен
                        time.sleep(0.5)
                        try:
                            test_proc = psutil.Process(pid)
                            if not test_proc.is_running():
                                success = True
                                method_used = f"завершение по имени ({proc_name})"
                                print(f"✅ Успех методом 4")
                        except psutil.NoSuchProcess:
                            success = True
                            method_used = f"завершение по имени ({proc_name})"
                            print(f"✅ Успех методом 4 (процесс не найден)")
                    else:
                        print(f"❌ Метод 4 ошибка: {result.stderr}")
                        
                except subprocess.TimeoutExpired:
                    print(f"⏰ Метод 4 превысил время ожидания")
                except Exception as e:
                    print(f"❌ Метод 4 ошибка: {e}")
            
            # МЕТОД 5: Завершение всех дочерних процессов
            if not success:
                print(f"⚡ МЕТОД 5: Завершение дочерних процессов")
                try:
                    children = proc.children(recursive=True)
                    for child in children:
                        try:
                            child.kill()
                            print(f"🔪 Завершен дочерний процесс: {child.pid}")
                        except:
                            pass
                    
                    # Теперь пробуем завершить родительский
                    proc.kill()
                    proc.wait(timeout=2)
                    
                    if not proc.is_running():
                        success = True
                        method_used = "завершение с дочерними процессами"
                        print(f"✅ Успех методом 5")
                        
                except Exception as e:
                    print(f"❌ Метод 5 ошибка: {e}")
            
            progress_window.destroy()
            
            if success:
                messagebox.showinfo("✅ Успех", 
                                   f"⚡ ТУРБО: Процесс {proc_name} успешно завершен!\n\n"
                                   f"Метод: {method_used}\n"
                                   f"PID: {pid}")
                self.refresh_apps()
            else:
                messagebox.showerror("❌ Неудача", 
                                   f"Не удалось завершить процесс {proc_name}\n\n"
                                   f"Возможные причины:\n"
                                   f"• Процесс защищен системой/антивирусом\n"
                                   f"• Критический системный процесс\n"
                                   f"• Процесс имеет более высокие привилегии\n"
                                   f"• Процесс заблокирован другим приложением\n\n"
                                   f"Попробуйте:\n"
                                   f"• Запустить программу от имени администратора\n"
                                   f"• Использовать Диспетчер задач\n"
                                   f"• Перезагрузить компьютер")
                
        except psutil.NoSuchProcess:
            progress_window.destroy()
            messagebox.showinfo("ℹ️ Информация", f"Процесс {proc_name} уже завершен")
            self.refresh_apps()
            
        except Exception as e:
            progress_window.destroy()
            error_msg = str(e)
            messagebox.showerror("❌ Критическая ошибка", 
                               f"Произошла критическая ошибка при завершении процесса:\n\n"
                               f"{error_msg}\n\n"
                               f"Обратитесь к системному администратору")

    def copy_app_info(self):
        """Копировать информацию о приложении в буфер обмена"""
        app_info = self.get_selected_app_info()
        if not app_info:
            return
        
        # Получаем путь к файлу приложения
        app_path = "Недоступен"
        try:
            if app_info['pid'] != 'N/A':
                pid = int(app_info['pid'])
                app_path = self.firewall_manager.get_app_path(pid)
                if not app_path:
                    app_path = "Недоступен"
        except (ValueError, TypeError, Exception):
            app_path = "Недоступен"
        
        # Получаем накопительные данные
        total_data = self.app_total_traffic.get(app_info['name'], {})
        total_sent_mb = total_data.get('sent_mb', 0)
        total_received_mb = total_data.get('received_mb', 0)
        total_mb = total_data.get('total_mb', 0)
        session_start = total_data.get('session_start', datetime.now())
        
        # Вычисляем время работы
        session_duration = datetime.now() - session_start
        hours = int(session_duration.total_seconds() // 3600)
        minutes = int((session_duration.total_seconds() % 3600) // 60)
        duration_str = f"{hours}ч {minutes}м" if hours > 0 else f"{minutes}м"
        
        # Проверяем статус блокировки
        is_blocked = self.firewall_manager.is_app_blocked(app_info['name'])
        block_status = "🚫 ЗАБЛОКИРОВАН" if is_blocked else "✅ Доступ разрешен"
            
        info_text = f"""⚡ ТУРБО РЕЖИМ
Приложение: {app_info['name']}
PID: {app_info['pid']}
Путь к файлу: {app_path}
Статус интернета: {block_status}
Время работы: {duration_str}

📡 Общий трафик за сессию:
Отправлено: {total_sent_mb:.2f} MB
Получено: {total_received_mb:.2f} MB
Всего: {total_mb:.2f} MB

📊 Текущая активность:
Соединений: {app_info['connections']}
Последняя активность: {app_info['last_activity']}"""
        
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(info_text)
            messagebox.showinfo("Успех", "⚡ ТУРБО: Информация скопирована в буфер обмена")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось скопировать: {e}")

    # ========== МЕТОДЫ FIREWALL ==========

    def block_app_internet(self):
        """Заблокировать доступ приложения в интернет"""
        app_info = self.get_selected_app_info()
        if not app_info:
            return
        
        app_name = app_info['name']
        
        if not self.admin_rights:
            messagebox.showerror("Ошибка", 
                               "Требуются права администратора для блокировки приложений.\n"
                               "Запустите программу от имени администратора.")
            return
        
        if not self.firewall_available:
            messagebox.showerror("Ошибка", 
                               "Windows Firewall недоступен.\n"
                               "Возможно, используется сторонний антивирус.")
            return
        
        if self.firewall_manager.is_app_blocked(app_name):
            messagebox.showinfo("Информация", f"Приложение {app_name} уже заблокировано")
            return
        
        try:
            pid = int(app_info['pid']) if app_info['pid'] != 'N/A' else None
            if not pid:
                messagebox.showwarning("Предупреждение", "PID процесса недоступен")
                return
            
            app_path = self.firewall_manager.get_app_path(pid)
            if not app_path:
                messagebox.showerror("Ошибка", "Не удалось получить путь к приложению")
                return
            
            result = messagebox.askyesno("Подтверждение блокировки", 
                                       f"⚡ ТУРБО РЕЖИМ\n\n"
                                       f"Заблокировать доступ в интернет для:\n\n"
                                       f"Приложение: {app_name}\n"
                                       f"PID: {pid}\n"
                                       f"Путь: {app_path}\n\n"
                                       f"Будет создано правило Windows Firewall.",
                                       icon='warning')
            
            if result:
                progress_window = self.show_progress_window("⚡ ТУРБО создание правила firewall...")
                
                try:
                    success, message = self.firewall_manager.create_block_rule(app_name, app_path)
                    
                    progress_window.destroy()
                    
                    if success:
                        messagebox.showinfo("Успех", f"⚡ ТУРБО: Приложение {app_name} заблокировано!\n{message}")
                        self.firewall_manager.refresh_blocked_status()
                        if hasattr(self, 'firewall_tree'):
                            self.refresh_firewall_table()
                        if hasattr(self, 'apps_tree'):
                            self.refresh_apps()
                    else:
                        messagebox.showerror("Ошибка", f"Не удалось заблокировать приложение:\n{message}")
                        
                except Exception as e:
                    progress_window.destroy()
                    messagebox.showerror("Ошибка", f"Ошибка блокировки: {str(e)}")
                    
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка обработки: {str(e)}")
    
    def unblock_app_internet(self):
        """Разблокировать доступ приложения в интернет"""
        app_info = self.get_selected_app_info()
        if not app_info:
            return
        
        self.unblock_app_internet_by_name(app_info['name'])

    def unblock_app_internet_by_name(self, app_name):
        """Разблокировать доступ приложения в интернет по имени"""
        if not self.admin_rights:
            messagebox.showerror("Ошибка", 
                               "Требуются права администратора для разблокировки приложений.")
            return
        
        if not self.firewall_manager.is_app_blocked(app_name):
            messagebox.showinfo("Информация", f"Приложение {app_name} не заблокировано")
            return
        
        result = messagebox.askyesno("Подтверждение разблокировки", 
                                   f"⚡ ТУРБО РЕЖИМ\n\n"
                                   f"Разблокировать доступ в интернет для:\n\n"
                                   f"Приложение: {app_name}\n\n"
                                   f"Правило firewall будет удалено.")
        
        if result:
            progress_window = self.show_progress_window("⚡ ТУРБО удаление правила firewall...")
            
            try:
                success, message = self.firewall_manager.remove_block_rule(app_name)
                
                progress_window.destroy()
                
                if success:
                    messagebox.showinfo("Успех", f"⚡ ТУРБО: Приложение {app_name} разблокировано!\n{message}")
                    self.refresh_firewall_table()
                    self.refresh_apps()
                else:
                    messagebox.showerror("Ошибка", f"Не удалось разблокировать приложение:\n{message}")
                    
            except Exception as e:
                progress_window.destroy()
                messagebox.showerror("Ошибка", f"Ошибка разблокировки: {str(e)}")

    def unblock_selected_firewall_app(self):
        """Разблокировать выбранное приложение из таблицы firewall"""
        app_info = self.get_selected_firewall_app()
        if app_info:
            self.unblock_app_internet_by_name(app_info['name'])
        else:
            messagebox.showwarning("Предупреждение", "Пожалуйста, выберите заблокированное приложение")
            
    def copy_firewall_app_name(self):
        """Копировать имя заблокированного приложения"""
        app_info = self.get_selected_firewall_app()
        if app_info:
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(app_info['name'])
                messagebox.showinfo("Успех", f"Имя приложения '{app_info['name']}' скопировано в буфер обмена")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось скопировать: {e}")
        else:
            messagebox.showwarning("Предупреждение", "Пожалуйста, выберите приложение")

    def show_progress_window(self, message):
        """Показать окно прогресса"""
        progress_window = tk.Toplevel(self.root)
        progress_window.title("⚡ ТУРБО Выполнение...")
        progress_window.geometry("350x120")
        progress_window.configure(bg='#2b2b2b')
        progress_window.transient(self.root)
        progress_window.grab_set()
        
        progress_window.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 50,
            self.root.winfo_rooty() + 50
        ))
        
        label = tk.Label(progress_window, text=message, bg='#2b2b2b', fg='white', 
                        font=('Arial', 10))
        label.pack(expand=True)
        
        progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
        progress_bar.pack(fill='x', padx=20, pady=10)
        progress_bar.start()
        
        progress_window.update()
        return progress_window

    def refresh_firewall_table(self):
        """Обновление таблицы заблокированных приложений"""
        if not hasattr(self, 'firewall_tree'):
            print("firewall_tree еще не создан, пропускаем обновление")
            return
            
        for item in self.firewall_tree.get_children():
            self.firewall_tree.delete(item)
        
        try:
            blocked_apps = self.firewall_manager.refresh_blocked_status()
            
            for app_name in blocked_apps:
                status = "🚫 Заблокировано"
                created_time = "⚡ ТУРБО"
                actions = "Двойной клик для разблокировки"
                
                self.firewall_tree.insert('', 'end', 
                                        values=(app_name, status, created_time, actions),
                                        tags=('blocked',))
            
            self.firewall_tree.tag_configure('blocked', background='#ff4757', foreground='white')
            
            if not blocked_apps:
                self.firewall_tree.insert('', 'end', 
                                        values=("⚡ ТУРБО: Нет заблокированных приложений", "", "", ""),
                                        tags=('empty',))
                self.firewall_tree.tag_configure('empty', background='#747d8c', foreground='white')
                
        except Exception as e:
            print(f"Ошибка обновления таблицы firewall: {e}")
            self.firewall_tree.insert('', 'end', 
                                    values=(f"⚡ ТУРБО Ошибка: {str(e)}", "", "", ""),
                                    tags=('error',))
            self.firewall_tree.tag_configure('error', background='#e74c3c', foreground='white')

    def cleanup_firewall_rules(self):
        """Очистить все правила firewall созданные анализатором"""
        if not self.admin_rights:
            messagebox.showerror("Ошибка", "Требуются права администратора")
            return
        
        blocked_apps = self.firewall_manager.get_blocked_apps()
        if not blocked_apps:
            messagebox.showinfo("Информация", "Нет правил для удаления")
            return
        
        result = messagebox.askyesno("Подтверждение", 
                                   f"⚡ ТУРБО РЕЖИМ\n\n"
                                   f"Удалить ВСЕ правила блокировки?\n\n"
                                   f"Будет удалено правил: {len(blocked_apps)}\n"
                                   f"Это действие нельзя отменить!",
                                   icon='warning')
        
        if result:
            progress_window = self.show_progress_window("⚡ ТУРБО удаление всех правил...")
            
            try:
                success, message = self.firewall_manager.cleanup_rules()
                progress_window.destroy()
                
                if success:
                    messagebox.showinfo("Успех", f"⚡ ТУРБО: Правила удалены!\n{message}")
                    if hasattr(self, 'firewall_tree'):
                        self.refresh_firewall_table()
                    if hasattr(self, 'apps_tree'):
                        self.refresh_apps()
                else:
                    messagebox.showerror("Ошибка", f"Ошибка очистки:\n{message}")
                    
            except Exception as e:
                progress_window.destroy()
                messagebox.showerror("Ошибка", f"Ошибка: {str(e)}")

    def test_firewall_functionality(self):
        """Тестировать функциональность firewall"""
        try:
            if not self.admin_rights:
                messagebox.showerror("Ошибка", "Требуются права администратора для тестирования")
                return
            
            self.firewall_status_label.config(text="⚡ ТУРБО тест firewall...")
            self.root.update()
            
            success = self.firewall_manager.manual_test_rule_creation()
            
            if success:
                self.firewall_status_label.config(text="✅ ⚡ ТУРБО тест пройден! Firewall работает корректно.")
                
                messagebox.showinfo("Тест пройден", 
                                   "✅ ⚡ ТУРБО: Windows Firewall работает корректно!\n\n"
                                   "Тестовое правило было создано и удалено успешно.\n"
                                   "Блокировка приложений должна работать.")
            else:
                self.firewall_status_label.config(text="❌ ⚡ ТУРБО тест НЕ пройден. Проверьте консоль.")
                messagebox.showerror("Тест НЕ пройден", 
                                   "❌ Обнаружены проблемы с Windows Firewall!\n\n"
                                   "Проверьте консоль для подробностей.")
            
            self.refresh_firewall_table()
            
        except Exception as e:
            self.firewall_status_label.config(text=f"❌ ⚡ ТУРБО ошибка теста: {str(e)}")
            messagebox.showerror("Ошибка", f"Ошибка при тестировании: {e}")

    def run_firewall_diagnostics(self):
        """Запустить диагностику firewall"""
        try:
            self.firewall_status_label.config(text="⚡ ТУРБО диагностика...")
            self.root.update()
            
            # Очищаем лог
            self.console_log = []
            
            # Перехватываем вывод print в лог
            original_stdout = sys.stdout
            
            class LogCapture:
                def __init__(self, log_list):
                    self.log_list = log_list
                    
                def write(self, text):
                    if text.strip():
                        self.log_list.append(text.strip())
                    original_stdout.write(text)
                    
                def flush(self):
                    original_stdout.flush()
            
            sys.stdout = LogCapture(self.console_log)
            
            try:
                # Запускаем диагностику
                self.firewall_manager.test_firewall_access()
                blocked_apps = self.firewall_manager.get_blocked_apps()
                
                self.firewall_status_label.config(text=f"⚡ ТУРБО диагностика завершена. Найдено: {len(blocked_apps)}")
                
                messagebox.showinfo("Диагностика завершена", 
                                   f"⚡ ТУРБО диагностика завершена!\n\n"
                                   f"Найдено заблокированных приложений: {len(blocked_apps)}\n"
                                   f"Подробная информация выведена в консоль.")
                
            finally:
                sys.stdout = original_stdout
            
            # Обновляем таблицу
            self.refresh_firewall_table()
            
        except Exception as e:
            self.firewall_status_label.config(text=f"❌ ⚡ ТУРБО ошибка диагностики: {str(e)}")
            messagebox.showerror("Ошибка", f"Ошибка диагностики: {e}")

    # ========== УПРАВЛЕНИЕ МОНИТОРИНГОМ ==========

    def start_monitoring(self):
        """⚡ ТУРБО запуск мониторинга"""
        if not self.monitoring:
            self.monitoring = True
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            
            # Очистка данных
            self.traffic_data.clear()
            self.protocol_stats.clear()
            self.bandwidth_data['sent'].clear()
            self.bandwidth_data['received'].clear()
            self.time_stamps.clear()
            self.last_stats = None
            
            self.app_traffic.clear()
            self.app_history.clear()
            self.previous_io_stats.clear()
            self.last_sort_order.clear()
            self.apps_update_counter = 0
            
            # ⚡ Очищаем накопительные счетчики трафика
            self.app_total_traffic.clear()
            
            # Сбрасываем счетчик общего сетевого трафика
            if hasattr(self, 'last_net_io'):
                delattr(self, 'last_net_io')
            
            self.firewall_available = self.firewall_manager.check_firewall_access()
            
            print("⚡ ТУРБО мониторинг запущен!")
            print("📊 Накопительные счетчики трафика сброшены")
            
            self.monitor_thread = threading.Thread(target=self.update_data, daemon=True)
            self.monitor_thread.start()

    def reset_traffic_stats(self):
        """⚡ ТУРБО сброс накопительной статистики трафика"""
        try:
            result = messagebox.askyesno("⚡ ТУРБО Сброс статистики", 
                                       "Сбросить ВСЮ накопительную статистику трафика?\n\n"
                                       "📊 Счетчики всех приложений будут обнулены\n"
                                       "⏰ Время работы приложений сбросится\n"
                                       "📈 Общая статистика начнется заново\n\n"
                                       "Это действие нельзя отменить!",
                                       icon='warning')
            
            if result:
                # Очищаем накопительные счетчики
                self.app_total_traffic.clear()
                
                # Сбрасываем текущую статистику
                self.app_traffic.clear()
                self.app_history.clear()
                
                # Обновляем интерфейс
                self.refresh_apps()
                
                # Показываем подтверждение
                messagebox.showinfo("✅ Успех", 
                                   "⚡ ТУРБО: Статистика трафика сброшена!\n\n"
                                   "📊 Все счетчики обнулены\n"
                                   "🔄 Накопление данных началось заново")
                
                print("⚡ ТУРБО: Статистика трафика сброшена пользователем")
                
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сбросить статистику: {e}")

    def stop_monitoring(self):
        """⚡ ТУРБО остановка мониторинга"""
        self.monitoring = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
        print("⚡ ТУРБО мониторинг остановлен!")

    def refresh_apps(self):
        """⚡ ТУРБО принудительное обновление списка приложений"""
        if not hasattr(self, 'apps_tree'):
            print("apps_tree еще не создан, пропускаем обновление")
            return
            
        active_apps = self.get_process_network_activity()
        self.update_apps_table(active_apps)
        
        current_time = datetime.now().strftime('%H:%M:%S')
        print(f"⚡ ТУРБО таблица приложений обновлена в {current_time}")

    def save_report(self):
        """⚡ ТУРБО сохранение отчета"""
        try:
            # Вычисляем общую статистику
            total_sent_mb = sum(data.get('sent_mb', 0) for data in self.app_total_traffic.values())
            total_received_mb = sum(data.get('received_mb', 0) for data in self.app_total_traffic.values())
            total_mb = total_sent_mb + total_received_mb
            total_apps = len(self.app_total_traffic)
            
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'mode': "⚡ TURBO MODE",
                'summary': {
                    'total_sent_mb': round(total_sent_mb, 2),
                    'total_received_mb': round(total_received_mb, 2),
                    'total_traffic_mb': round(total_mb, 2),
                    'total_apps_monitored': total_apps
                },
                'bandwidth_data': {
                    'sent': list(self.bandwidth_data['sent']),
                    'received': list(self.bandwidth_data['received'])
                },
                'protocol_stats': dict(self.protocol_stats),
                'time_stamps': list(self.time_stamps),
                'app_traffic': {app: {
                    'sent': data['sent'],
                    'received': data['received'],
                    'connections': data['connections'],
                    'last_activity': data['last_activity'].isoformat() if data['last_activity'] else None
                } for app, data in self.app_traffic.items()},
                # ⚡ Добавляем накопительные данные в мегабайтах
                'app_total_traffic_mb': {app: {
                    'sent_mb': round(data['sent_mb'], 2),
                    'received_mb': round(data['received_mb'], 2),
                    'total_mb': round(data['total_mb'], 2),
                    'session_start': data['session_start'].isoformat() if data['session_start'] else None
                } for app, data in self.app_total_traffic.items()},
                'firewall_blocked_apps': self.firewall_manager.get_blocked_apps() if hasattr(self, 'firewall_manager') else []
            }
            
            filename = f"network_report_turbo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("Сохранено", 
                              f"⚡ ТУРБО отчет сохранен в файл: {filename}\n\n"
                              f"📊 Общая статистика:\n"
                              f"↑ Отправлено: {total_sent_mb:.2f} MB\n"
                              f"↓ Получено: {total_received_mb:.2f} MB\n"
                              f"📱 Приложений: {total_apps}")
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сохранить отчет: {e}")


def main():
    """⚡ Главная функция запуска ТУРБО анализатора"""
    print("=" * 60)
    print("⚡ ЗАПУСК ТУРБО-АНАЛИЗАТОРА СЕТЕВОГО ТРАФИКА ⚡")
    print("=" * 60)
    print("🚀 ТОЛЬКО ТУРБО РЕЖИМ!")
    print("🔥 Максимальная производительность и экономия ресурсов")
    print("⚡ ОПТИМИЗИРОВАННЫЕ обновления и упрощенные расчеты")
    print("📱 АВТОМАТИЧЕСКИ открывается вкладка 'Приложения'")
    print("▶️ АВТОМАТИЧЕСКИЙ ЗАПУСК мониторинга через 2 сек")
    print("🚫 Переключение в обычный режим ОТКЛЮЧЕНО")
    print("=" * 60)
    
    root = tk.Tk()
    
    # Устанавливаем иконку в заголовке (если возможно)
    try:
        root.iconname("⚡ Турбо Анализатор")
    except:
        pass
    
    app = NetworkTrafficAnalyzer(root)
    
    print("✅ Интерфейс создан успешно!")
    print("⚡ ТОЛЬКО ТУРБО РЕЖИМ - наслаждайтесь скоростью!")
    print("📱 Вкладка 'Приложения' открыта автоматически")
    print("▶️ Мониторинг запустится автоматически!")
    print("🎉 Анализатор полностью готов к работе!")
    
    # Запускаем главный цикл
    root.mainloop()
    
    print("👋 ТУРБО-анализатор завершен. До свидания!")


if __name__ == "__main__":
    main()