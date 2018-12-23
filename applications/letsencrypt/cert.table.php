<?php
$table = new DatabaseTableBuilder;

$table->addColumn("cn","VARCHAR(50)")->setAsPrimaryKey();
$table->addColumn("domains");
$table->addColumn("lastIssued","INT");
$table->addColumn("nextIssue","INT");
$table->addColumn("live","INT(1)")->defaultValue(0);

return $table;