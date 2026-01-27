```
python3 -m venv [PROJECT_ROOT]/.venv
cd PROJECT_ROOT
source ./.venv/bin/activate
pip install west
west init
west update
```

```
west build --pristine -b arduino_nano_33_iot app
```

``
# create workspace outside repo
mkdir -p ~/zephyr-workspace && cd ~/zephyr-workspace
west init -m /home/doug/git/iot-foundry-zephyr-endpoint
west update
/home/doug/git/iot-foundry-zephyr-endpoint/patches/apply_patches.sh
west build -b arduino_nano_33_iot /home/doug/git/iot-foundry-zephyr-endpoint
```