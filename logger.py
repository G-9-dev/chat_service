import logging

# Create a logger
logger = logging.getLogger('ChatLogger')
logger.setLevel(logging.DEBUG)

# Create a file handler for the logger
handler = logging.FileHandler('chat.log')
handler.setLevel(logging.DEBUG)

# Create a formatter and add it to the handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(handler)
