# Use an official Python runtime as a parent image
FROM python:3.12.2

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /.

# Copy the contents of the current directory into the container at /agent
COPY . /

# Copy the virtual environment from the host machine to the container
COPY ./.venv /.venv

# Set the virtual environment as the active Python environment
ENV VIRTUAL_ENV=/.venv
ENV PATH="$VIRTUAL_ENV/Scripts:$PATH"
ENV PATH="$VIRTUAL_ENV/Lib:$PATH"

# Install requirements
RUN pip install -r requirements.txt

#COPY ./pqcrypto/pqcrypto/_kem /usr/local/lib/python3.12/site-packages/pqcrypto/_kem
#COPY ./pqcrypto/pqcrypto/kem/init.py /usr/local/lib/python3.12/site-packages/pqcrypto/kem
#COPY ./pqcrypto/pqcrypto/_sign /usr/local/lib/python3.12/site-packages/pqcrypto/_sign
#COPY ./pqcrypto/pqcrypto/sign/init.py /usr/local/lib/python3.12/site-packages/pqcrypto/sign

# Update package lists and install nano
RUN apt-get update && apt-get install -y nano && apt-get install -y net-tools

# Expose the port your Tornado application listens on
EXPOSE 8888

# Command to run the application
CMD ["python", "CA.py"]


