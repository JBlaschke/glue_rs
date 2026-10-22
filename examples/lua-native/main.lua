local inspect = require("inspect")
local temperature = require("temperature")

local samples = {18, 20, 22}
local total = 0
for _, value in ipairs(samples) do
    total = total + value
end
local mean = total / #samples

print("samples_c=" .. inspect(samples))
print(string.format("mean_c=%.2f mean_f=%.2f", mean, temperature.fahrenheit(mean)))
print("argument=" .. (arg[1] or "friend"))
