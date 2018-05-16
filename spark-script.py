from pyspark.sql import SparkSession
from minebench import Minebench, InputUtils, FormatUtils


spark = SparkSession.builder.getOrCreate()

partitions = int(spark.conf.get("spark.executor.instances")) \
    * int(spark.conf.get("spark.executor.cores"))

blocks_df = (spark.read.option("header", "false") \
    .option("mode", "DROPMALFORMED").csv("hdfs:///50k_blocks.csv")) \
    .repartition(partitions)

hashes_rdd = blocks_df.rdd \
    .map(lambda row: Minebench.get_block_header(row,
                                                bits=0x1FFFFFFF,
                                                sequential_nonce=True).mine())

hashes_rdd.saveAsTextFile("hdfs:///minebench")
