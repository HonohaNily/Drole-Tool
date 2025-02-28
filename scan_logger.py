"""
Logging module for MineScan
Handles logging of scan operations and findings
"""

import logging
import os
from datetime import datetime
from typing import Optional

class ScanLogger:
    """Handles logging for the scanner"""
    
    def __init__(self, log_level: int = logging.INFO, log_file: Optional[str] = None):
        self.logger = logging.getLogger('minescan')
        self.logger.setLevel(log_level)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Add file handler if log file specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
            
    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)
        
    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)
        
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
        
    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)
        
    def critical(self, message: str):
        """Log critical message"""
        self.logger.critical(message)
