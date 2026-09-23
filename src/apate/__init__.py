import logging

logger = logging.getLogger('apate')

logger.setLevel(logging.INFO)

Formatter = logging.Formatter("%(levelname)s:%(asctime)s:%(message)s")

file_handler = logging.FileHandler("logs/tasks.log")
file_handler.setFormatter(Formatter)

logger.addHandler(file_handler)