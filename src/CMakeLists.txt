include_directories(.)

add_executable(
  test

  test.cpp
)
target_link_libraries(
  test

  snark
)
target_include_directories(
  test

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(
  test-gadget

  test-gadget.cpp
)
target_link_libraries(
  test-gadget

  snark
)
target_include_directories(
  test-gadget

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_knowledge_of_preimage

  test_knowledge_of_preimage.cpp
)
target_link_libraries(
  test_knowledge_of_preimage

  snark
)
target_include_directories(
  test_knowledge_of_preimage

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_sha256

  test_sha256.cpp
)
target_link_libraries(
  test_sha256

  snark
)
target_include_directories(
  test_sha256

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_double_sha256

  test_double_sha256.cpp
)
target_link_libraries(
  test_double_sha256

  snark
)
target_include_directories(
  test_double_sha256

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_knowledge_of_preimage_ripemd160

  test_knowledge_of_preimage_ripemd160.cpp
)
target_link_libraries(
  test_knowledge_of_preimage_ripemd160

  snark
)
target_include_directories(
  test_knowledge_of_preimage_ripemd160

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_PGHR13

  test_PGHR13.cpp
)
target_link_libraries(
  test_PGHR13

  snark
)
target_include_directories(
  test_PGHR13

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_exp

  test_exp.cpp
)
target_link_libraries(
  test_exp

  snark
)
target_include_directories(
  test_exp

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_scalarmul

  test_scalarmul.cpp
)
target_link_libraries(
  test_scalarmul

  snark
)
target_include_directories(
  test_scalarmul

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  scalarmul

  scalarmul.cpp
)
target_link_libraries(
  scalarmul

  snark
)
target_include_directories(
  scalarmul

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_equality

  test_equality.cpp
)
target_link_libraries(
  test_equality

  snark
)
target_include_directories(
  test_equality

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  pedersen

  pedersen.cpp
)
target_link_libraries(
  pedersen

  snark
)
target_include_directories(
  pedersen

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  Proof_of_Assets

  Proof_of_Assets.cpp
)
target_link_libraries(
  Proof_of_Assets

  snark
)
target_include_directories(
  Proof_of_Assets

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_if_equality

  test_if_equality.cpp
)
target_link_libraries(
  test_if_equality

  snark
)
target_include_directories(
  test_if_equality

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_POA

  test_POA.cpp
)
target_link_libraries(
  test_POA

  snark
)
target_include_directories(
  test_POA

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  thread

  thread.cpp
)
target_link_libraries(
  thread

  snark
)
target_include_directories(
  thread

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  scalarmul_threads

  scalarmul_threads.cpp
)
target_link_libraries(
  scalarmul_threads

  snark
)
target_include_directories(
  scalarmul_threads

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  scalarmul_threads_pointers

  scalarmul_threads_pointers.cpp
)
target_link_libraries(
  scalarmul_threads_pointers

  snark
)
target_include_directories(
  scalarmul_threads_pointers

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_POA_final

  test_POA_final.cpp
)
target_link_libraries(
  test_POA_final

  snark
)
target_include_directories(
  test_POA_final

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  Pedersen_commitment

  Pedersen_commitment.cpp
)
target_link_libraries(
  Pedersen_commitment

  snark
)
target_include_directories(
  Pedersen_commitment

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  scalarmul_bn

  scalarmul_bn.cpp
)
target_link_libraries(
  scalarmul_bn

  snark
)
target_include_directories(
  scalarmul_bn

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  pedersen_bn

  pedersen_bn.cpp
)
target_link_libraries(
  pedersen_bn

  snark
)
target_include_directories(
  pedersen_bn

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  POA_bn

  POA_bn.cpp
)
target_link_libraries(
  POA_bn

  snark
)
target_include_directories(
  POA_bn

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_POA_bn

  test_POA_bn.cpp
)
target_link_libraries(
  test_POA_bn

  snark
)
target_include_directories(
  test_POA_bn

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_POA_final_bn

  test_POA_final_bn.cpp
)
target_link_libraries(
  test_POA_final_bn

  snark
)
target_include_directories(
  test_POA_final_bn

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  random

  random.cpp
)
target_link_libraries(
  random

  snark
)
target_include_directories(
  random

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  POA_final_bn

  POA_final_bn.cpp
)
target_link_libraries(
  POA_final_bn

  snark
)
target_include_directories(
  POA_final_bn

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  scalarmul_final

  scalarmul_final.cpp
)
target_link_libraries(
  scalarmul_final

  snark
)
target_include_directories(
  scalarmul_final

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  pedersen_final

  pedersen_final.cpp
)
target_link_libraries(
  pedersen_final

  snark
)
target_include_directories(
  pedersen_final

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  POA_final

  POA_final.cpp
)
target_link_libraries(
  POA_final

  snark
)
target_include_directories(
  POA_final

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  test_POA_ecc

  test_POA_ecc.cpp
)
target_link_libraries(
  test_POA_ecc

  snark
)
target_include_directories(
  test_POA_ecc

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  packing_gadget

  packing_gadget.cpp
)
target_link_libraries(
  packing_gadget

  snark
)
target_include_directories(
  packing_gadget

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  FF_gadget

  FF_gadget.cpp
)
target_link_libraries(
  FF_gadget

  snark
)
target_include_directories(
  FF_gadget

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  sha256

  sha256.cpp
)
target_link_libraries(
  sha256

  snark
)
target_include_directories(
  sha256

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)
add_executable(
  ripemd160

  ripemd160.cpp
)
target_link_libraries(
  ripemd160

  snark
)
target_include_directories(
  ripemd160

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

