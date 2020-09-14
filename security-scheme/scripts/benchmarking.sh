#!/bin/bash

readonly TIMESTAMP=$(date +%s)

readonly ITERATIONS=5
readonly OUTPUT_DIR="benchmarks"
readonly EXECUTABLE="../build/security-scheme-javacard"

# check if output dir exists
[ ! -d ${OUTPUT_DIR} ] && mkdir ${OUTPUT_DIR}

# check if the executable exists
[ ! -f ${EXECUTABLE} ] && exit

computation_average=0
verification_average=0
for i in $(seq 1 ${ITERATIONS}); do
  echo "[+] Running ${i}/${ITERATIONS}..."
  elapsed_time_data=$(${EXECUTABLE} | grep -a "Elapsed time")

  # raw times
  computation_show_stage_1_time=$(echo "${elapsed_time_data}" | grep "compute_show_stage_1" | cut -d' ' -f6)
  computation_show_stage_2_time=$(echo "${elapsed_time_data}" | grep "compute_show_stage_2" | cut -d' ' -f6)
  total_computation_show=$(echo "scale=6; ${computation_show_stage_1_time}+${computation_show_stage_2_time}" | bc | sed 's/^\./0./')
  verification_time=$(echo "${elapsed_time_data}" | grep "verification" | cut -d' ' -f6)
  echo "${total_computation_show};${computation_show_stage_1_time};${computation_show_stage_2_time};${verification_time}" >>"${OUTPUT_DIR}/${TIMESTAMP}_raw.txt"

  # partial average
  computation_average=$(echo "scale=6; ${computation_average}+${total_computation_show}" | bc)
  verification_average=$(echo "scale=6; ${verification_average}+${verification_time}" | bc)
done

# average times
computation_average=$(echo "scale=6; ${computation_average}/${ITERATIONS}" | bc | sed 's/^\./0./')
verification_average=$(echo "scale=6; ${verification_average}/${ITERATIONS}" | bc | sed 's/^\./0./')
echo "${computation_average};${verification_average}" >>"${OUTPUT_DIR}/${TIMESTAMP}_csv.txt"
