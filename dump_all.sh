#./cleanup.sh
find . -type f -regextype posix-extended \
  -regex '.*\.(py|cpp|h|i|txt|md|html|js|toml)$' \
  -not -name 'all.txt' \
  -not -regex '.*/node_modules.*' \
  -exec awk 'FNR==1{print "\n//" FILENAME "\n"} {print}' {} + > all.txt
