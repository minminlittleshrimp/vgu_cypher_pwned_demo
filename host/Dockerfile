FROM ubuntu:20.04

# Install required packages for 32-bit compilation
RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y \
    build-essential \
    gcc-multilib \
    libc6-dev-i386 \
    socat && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m ctfuser && \
    mkdir -p /home/ctfuser/app && \
    chown -R root:ctfuser /home/ctfuser && \
    chmod 750 /home/ctfuser

# Create a flag file, set strict permissions
RUN echo "vgucypher{st@ck_0verf0w_d3m0}" > /flag.txt && \
    chown root:ctfuser /flag.txt && \
    chmod 440 /flag.txt

# Copy the challenge source code and compile the binary
WORKDIR /home/ctfuser/app
COPY runway1.c /home/ctfuser/app/

# Compile the challenge program without RELRO
RUN gcc -m32 -z relro -fno-stack-protector -z noexecstack -no-pie -o runway1 runway1.c && \
    chown root:ctfuser /home/ctfuser/app/runway1 && \
    chmod 750 /home/ctfuser/app/runway1 && \
    chmod 550 /home/ctfuser/app

RUN rm /home/ctfuser/app/runway1.c

# Switch to the non-root user
USER ctfuser

# Expose port for the challenge
EXPOSE 1338

# Run the challenge with socat to expose it over TCP
ENTRYPOINT ["socat", "TCP-LISTEN:1338,fork", "EXEC:/home/ctfuser/app/runway1"]
