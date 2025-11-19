import logging
import sys
from rich.logging import RichHandler

def setup_logging(level=logging.INFO):
    """Setup logging configuration with rich handler"""
    
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            RichHandler(rich_tracebacks=True),
            logging.FileHandler('cis_automation.log')
        ]
    )
    
    # Suppress noisy logs
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("fabric").setLevel(logging.WARNING)