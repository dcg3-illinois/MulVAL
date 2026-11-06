#!/bin/sh
# This scripts invokes the risk-assessment algorithm by Wang et al.
# Author: Su Zhang, Xinming Ou
# Copyright (C) 2011, Argus Cybersecurity Lab, Kansas State University

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.
CLASSPATH=$CLASSPATH:$MULVALROOT/bin/metrics:$JDBC_JAR

# Copy the JDBC connection config into the working dir for getConnection().
if [ -f /opt/mulval-cve/config.txt ] && [ ! -f config.txt ]; then
    cp /opt/mulval-cve/config.txt ./config.txt
fi

# ``-method METHOD`` selects the DB lookup mode for independentAlgoSumm; it is
# NOT a render.sh option. Split the args: -method+value go to java, everything
# else goes to render.sh.
RENDER_OPTS=""
JAVA_ARGS=""
prev=
for arg in "$@"; do
    if [ "$prev" = "-method" ]; then
        # this is the value of -method
        JAVA_ARGS="$JAVA_ARGS $arg"
        prev=
        continue
    fi
    if [ "$arg" = "-method" ]; then
        JAVA_ARGS="$JAVA_ARGS $arg"
        prev=-method
        continue
    fi
    RENDER_OPTS="$RENDER_OPTS $arg"
done
if [ "$prev" = "-method" ]; then
    # a bare -method with no value -> treat as default (column)
    prev=
fi

java -cp $CLASSPATH independentAlgoSumm $JAVA_ARGS
mv VERTICES_METRICS.CSV VERTICES.CSV
render.sh $RENDER_OPTS
