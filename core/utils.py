from datetime import datetime
from typing import List, Dict
from pathlib import Path
import json
import logging
from core.custom_logger.logger import setup_logger


setup_logger()
logger = logging.getLogger(__name__)


async def save_results(results: List[Dict], filename: str = None) -> str:
    try:
        # Generate filename with timestamp if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"

        if not filename.endswith('.json'):
            filename += '.json'

        results_dir = "scan_results"
        Path(results_dir).mkdir(exist_ok=True)

        file_path = Path(results_dir) / filename

        # Add metadata to results
        output_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "filename": str(file_path)
            },
            "results": results
        }

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Scan results saved to: {file_path}")
        return str(file_path)

    except IOError as e:
        error_msg = f"Error saving results to file: {str(e)}"
        logger.error(error_msg)
        raise IOError(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error saving results: {str(e)}"
        logger.error(error_msg)
        raise