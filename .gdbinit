target remote :1337
catch signal SIGSYS
commands
cont
end
