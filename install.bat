rem
rem Script de Instalacion del ATM Emulator
rem
del log-output.txt
rmdir node_modules /s /q
git config --global url."https://".insteadOf git://
call npm install
