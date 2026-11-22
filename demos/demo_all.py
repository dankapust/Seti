"""
Комплексный сквозной демонстрационный сценарий (Этапы 1 - 5).
Запускает последовательно все демонстрационные сценарии этапов 1..5.
"""

import os
import sys
import subprocess
import time

# Config UTF-8 output for Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

DEMOS = [
    ("Этап 1: Сетевой транспорт, бинарный протокол и таймауты", "demos/demo_stage1.py"),
    ("Этап 2: Идентичность Ed25519, Kademlia DHT, топологии Bootstrap и персистентность", "demos/demo_stage2.py"),
    ("Этап 3: Реплицированное хранилище, цифровые подписи, кворум и падение хранителя", "demos/demo_stage3.py"),
    ("Этап 4: Защищенный канал связи, X25519 ECDH, ChaCha20-Poly1305, перехватчик и Replay Shield", "demos/demo_stage4.py"),
    ("Этап 5: Многопереходные туннели, E2E AEAD-шифрование и восстановление при аварии узла", "demos/demo_stage5.py"),
]

def main():
    print("=" * 80)
    print("  ЗАПУСК ПОЛНОЙ СКВОЗНОЙ ДЕМОНСТРАЦИИ ВСЕХ ЭТАПОВ КУРСОВОГО ПРОЕКТА (1-5)  ")
    print("=" * 80)
    
    start_time = time.time()
    
    for i, (title, script) in enumerate(DEMOS, 1):
        print("\n" + "#" * 80)
        print(f"  [ДЕМОНСТРАЦИЯ {i}/5] {title}")
        print(f"  Скрипт: {script}")
        print("#" * 80 + "\n")
        
        script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", script))
        res = subprocess.run([sys.executable, script_path], env=os.environ.copy())
        if res.returncode != 0:
            print(f"\n[ОШИБКА] Сценарий {script} завершился с кодом ошибки {res.returncode}")
            sys.exit(res.returncode)
        
        print(f"\n[OK] Демонстрация этапа {i} успешно завершена!")
        time.sleep(1)

    total_elapsed = time.time() - start_time
    print("\n" + "=" * 80)
    print(f"  ВСЕ 5 ЭТАПОВ УСПЕШНО ПРОДЕМОНСТРИРОВАНЫ ЗА {total_elapsed:.2f} СЕК!  ")
    print("=" * 80)

if __name__ == "__main__":
    main()
