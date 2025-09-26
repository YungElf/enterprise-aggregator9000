import os

from flask_app.web.constants import LOCAL_ENV


def get_my_env():
    if "EPAAS_ENV" in os.environ:
        return os.environ["EPAAS_ENV"][0:2].lower()
    else:
        return LOCAL_ENV