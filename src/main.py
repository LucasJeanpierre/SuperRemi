from tools.ModularMath import ModularMath
import logging

logo = [
"   _____                       _____                _ ",
"  / ____|                     |  __ \\              (_)",
" | (___  _   _ _ __   ___ _ __| |__) |___ _ __ ___  _ ",
"  \\___ \\| | | | '_ \\ / _ \\ '__|  _  // _ \\ '_ ` _ \\| |",
"  ____) | |_| | |_) |  __/ |  | | \\ \\  __/ | | | | | |",
" |_____/ \\__,_| .__/ \\___|_|  |_|  \\_\\___|_| |_| |_|_|",
"              | |                                     ",
"              |_|                                     ",]

if __name__ == "__main__":
    for line in logo:
        print(line)
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
    logging.info("Application started")
