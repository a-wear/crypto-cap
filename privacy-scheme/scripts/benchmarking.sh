#!/bin/bash

readonly TIMESTAMP=$(date +%s)

readonly ITERATIONS=5
readonly OUTPUT_DIR="benchmarks"
readonly EXECUTABLE="../build/privacy-scheme-multos"

# check if output dir exists
[ ! -d ${OUTPUT_DIR} ] && mkdir ${OUTPUT_DIR}

# check if the executable exists
[ ! -f ${EXECUTABLE} ] && exit

computation_average=0
communication_average=0
computation_communication_average=0
verification_average=0
for i in $(seq 1 ${ITERATIONS}); do
  echo "[+] Running ${i}/${ITERATIONS}..."
  elapsed_time_data=$(${EXECUTABLE} | grep -a "Elapsed time")

  # raw times
  computation_time=$(echo "${elapsed_time_data}" | grep "compute_proof_of_key" | cut -d' ' -f6)
  communication_time=$(echo "${elapsed_time_data}" | grep "communication_proof_of_key" | cut -d' ' -f6)
  computation_communication_time=$(echo "scale=6; ${computation_time}+${communication_time}" | bc | sed 's/^\./0./')
  verification_time=$(echo "${elapsed_time_data}" | grep "verification" | cut -d' ' -f6)
  echo "${computation_communication_time};${computation_time};${communication_time};${verification_time}" >>"${OUTPUT_DIR}/${TIMESTAMP}_raw.txt"

  # partial average
  computation_average=$(echo "scale=6; ${computation_average}+${computation_time}" | bc)
  communication_average=$(echo "scale=6; ${communication_average}+${communication_time}" | bc)
  computation_communication_average=$(echo "scale=6; ${computation_communication_average}+${computation_communication_time}" | bc)
  verification_average=$(echo "scale=6; ${verification_average}+${verification_time}" | bc)
done

# average times
computation_average=$(echo "scale=6; ${computation_average}/${ITERATIONS}" | bc | sed 's/^\./0./')
communication_average=$(echo "scale=6; ${communication_average}/${ITERATIONS}" | bc | sed 's/^\./0./')
computation_communication_average=$(echo "scale=6; ${computation_communication_average}/${ITERATIONS}" | bc | sed 's/^\./0./')
verification_average=$(echo "scale=6; ${verification_average}/${ITERATIONS}" | bc | sed 's/^\./0./')
echo "${computation_communication_average};${computation_average};${communication_average};${verification_average}" >>"${OUTPUT_DIR}/${TIMESTAMP}_csv.txt"
