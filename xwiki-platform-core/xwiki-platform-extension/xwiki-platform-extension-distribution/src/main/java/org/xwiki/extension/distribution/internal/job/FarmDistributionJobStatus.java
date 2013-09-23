/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.extension.distribution.internal.job;

import java.util.List;

import org.xwiki.extension.distribution.internal.job.step.DistributionStep;
import org.xwiki.extension.distribution.internal.job.step.UpgradeModeDistributionStep;
import org.xwiki.extension.distribution.internal.job.step.UpgradeModeDistributionStep.UpgradeMode;
import org.xwiki.logging.LoggerManager;
import org.xwiki.observation.ObservationManager;

/**
 * @version $Id$
 * @since 5.0M1
 */
public class FarmDistributionJobStatus extends DistributionJobStatus<DistributionRequest>
{
    /**
     * Serialization identifier.
     */
    private static final long serialVersionUID = 1L;

    private UpgradeModeDistributionStep upgradeModeStep;

    public FarmDistributionJobStatus(DistributionRequest request, ObservationManager observationManager,
        LoggerManager loggerManager, List<DistributionStep> steps)
    {
        super(request, observationManager, loggerManager, steps);

        init();
    }

    public FarmDistributionJobStatus(DistributionJobStatus<DistributionRequest> status,
        ObservationManager observationManager, LoggerManager loggerManager)
    {
        super(status, observationManager, loggerManager);

        init();
    }

    private void init()
    {
        /* TODO: enabled when the UI will be a bit more usable in all in one mode
        if (getSteps() != null) {
            for (DistributionStep step : getSteps()) {
                if (step instanceof UpgradeModeDistributionStep) {
                    this.upgradeModeStep = (UpgradeModeDistributionStep) step;
                }
            }
        }
        */
    }

    public UpgradeMode getUpgradeMode()
    {
        return this.upgradeModeStep != null ? this.upgradeModeStep.getUpgradeMode() : UpgradeMode.WIKI;
    }
}
