from glob import glob
from os import remove

from django.conf import settings

from django_rq import job


@job
def delete_uploaded_files():

    files = glob(f"{settings.MEDIA_ROOT}/docs/*")

    for file in files:
        remove(file)
