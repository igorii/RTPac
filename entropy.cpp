#include <math.h>
#include <stdio.h>

double safe_log (double x)
{
    double rlt = log (x);
    if (isfinite(rlt)) {
        return rlt / log (2);  // Convert to base 2
    } else {
        return 0;
    }
}

double element_frequency (unsigned long occurrences, unsigned long count)
{
    return ((double) occurrences) / count;
}

double entropy_of_distribution (
        unsigned long  count,
        unsigned long *distribution,
        unsigned long  classes
        )
{
    int i;
    double sum, freq;
    for (i = 0; i < classes; ++i) {
        freq = element_frequency(distribution[i], count);
        sum += freq * safe_log(freq);
    }

    return 0 - sum;
}

double relative_entropy (
        unsigned long  count1,
        unsigned long *distribution1,
        unsigned long  count2,
        unsigned long *distribution2,
        unsigned long  classes
        )
{
    int i;
    double sum, freq1, freq2;

    for (i = 0; i < classes; ++i) {
        freq1 = element_frequency(distribution1[i], count1);
        freq2 = element_frequency(distribution2[i], count2);
        sum += freq1 * safe_log ( freq1 / freq2 );
    }

    return 0 - sum;
}
